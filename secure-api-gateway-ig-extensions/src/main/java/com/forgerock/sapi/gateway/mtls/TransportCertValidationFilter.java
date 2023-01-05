/*
 * Copyright © 2020-2022 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.mtls;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.function.BiFunction;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.ApiClient;
import com.forgerock.sapi.gateway.fapi.FAPIUtils;
import com.forgerock.sapi.gateway.fapi.v1.FAPIAdvancedDCRValidationFilter.CertificateFromHeaderSupplier;
import com.forgerock.sapi.gateway.jwks.FetchApiClientJwksFilter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Filter to validate that the client's MTLS transport certificate is valid.
 *
 * This filter depends on the {@link JWKSet} containing the keys for this {@link ApiClient} being present in
 * the {@link AttributesContext}.
 *
 * The certificate for the request is supplied by the clientTlsCertificateSupplier, which is then matched with one of
 * the JWKs in the JWKSet.
 *
 * Certificate matching is achieved by transforming the incoming client certificate into a JWK and then testing for
 * equality between the x5c[0] values. The x5c[0] represents the base64 encoded DER PKIX certificate value. The first
 * item in the x5c array must be the certificate, therefore we only check this entry and not the full chain.
 *
 * Spec for JWK.x5c field: https://www.rfc-editor.org/rfc/rfc7517#section-4.7
 */
public class TransportCertValidationFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Function which returns the client's PEM encoded x509 certificate which is used for MTLS as a String.
     */
    private final BiFunction<Context, Request, String> clientTlsCertificateSupplier;

    /**
     * Optionally validate that the JWK entry in the JWKS has a "use" value that matches this value.
     *
     * If this is configured as null, then checking of the use field will be skipped.
     */
    private final String keyUse;

    public TransportCertValidationFilter(BiFunction<Context, Request, String> clientTlsCertificateSupplier) {
        this(clientTlsCertificateSupplier, null);
    }

    public TransportCertValidationFilter(BiFunction<Context, Request, String> clientTlsCertificateSupplier, String keyUse) {
        Reject.ifNull(clientTlsCertificateSupplier, "clientTlsCertificate must be provided");
        this.clientTlsCertificateSupplier = clientTlsCertificateSupplier;
        this.keyUse = keyUse;
    }

    private Response createErrorResponse(String message) {
        return new Response(Status.BAD_REQUEST).setEntity(json(object(field("error_description", message))));
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        logger.debug("({}) attempting to validate transport cert", FAPIUtils.getFapiInteractionIdForDisplay(context));
        final String clientCertPem = clientTlsCertificateSupplier.apply(context, request);
        if (clientCertPem == null) {
            return Promises.newResultPromise(createErrorResponse("client tls certificate not found"));
        }

        final X509Certificate certificate;
        try {
            certificate = parseCertificate(clientCertPem);
        } catch (CertificateException e) {
            logger.warn("("+  FAPIUtils.getFapiInteractionIdForDisplay(context) + ") transport cert not valid", e);
            return Promises.newResultPromise(createErrorResponse("client tls certificate is not valid"));
        }

        // JWK x5c string representation of this cert to validate against a x5c value in the JWKS
        final String x5cForClientCert;
        try {
            x5cForClientCert = getX5cForClientCert(certificate);
        } catch (JOSEException e) {
            logger.warn("("+  FAPIUtils.getFapiInteractionIdForDisplay(context) + ") transport could not be parsed", e);
            return Promises.newResultPromise(createErrorResponse("client tls certificate is not valid"));
        }

        final JWKSet apiClientJwkSet = getJwkSet(context);
        if (!tlsClientCertExistsInJwkSet(apiClientJwkSet, x5cForClientCert)) {
            logger.debug("({}) transport cert failed validation: not present in JWKS", FAPIUtils.getFapiInteractionIdForDisplay(context));
            return Promises.newResultPromise(createErrorResponse("client tls certificate not found in JWKS for software statement"));
        }
        logger.debug("({}) transport cert validated successfully", FAPIUtils.getFapiInteractionIdForDisplay(context));
        return next.handle(context, request);
    }

    private JWKSet getJwkSet(Context context) {
        final JWKSet apiClientJwkSet = FetchApiClientJwksFilter.getApiClientJwkSetFromContext(context);
        if (apiClientJwkSet == null) {
            logger.error("({}) apiClientJwkSet not found in request context", FAPIUtils.getFapiInteractionIdForDisplay(context));
            throw new IllegalStateException("apiClientJwkSet not found in request context");
        }
        return apiClientJwkSet;
    }

    private X509Certificate parseCertificate(String cert) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8)));
        if (!(certificate instanceof X509Certificate)) {
            throw new CertificateException("client tls cert must be in X.509 format");
        }
        final X509Certificate x509Cert = (X509Certificate) certificate;
        x509Cert.checkValidity();
        return x509Cert;
    }

    /**
     * Converts the X509 certificate into x5c format (see https://www.rfc-editor.org/rfc/rfc7517#section-4.7) so
     * that it can be compared to the x5c values present for the JWK objects in the JWKS
     *
     * @param certificate X509Certificate to get the x5c value for
     * @return String representing the x5c value of the cert
     * @throws JOSEException if the certificate cannot be converted into a JWK
     */
    private String getX5cForClientCert(X509Certificate certificate) throws JOSEException {
        if (certificate.getPublicKey() instanceof RSAPublicKey) {
            return RSAKey.parse(certificate).getX509CertChain().get(0).toString();
        }

        throw new IllegalStateException("Unsupported certificate type: " + certificate.getClass());
    }

    /**
     * Check if the client's transport cert exists in the JWKSet by comparing JWK.x5c values with the supplied clientCertX5c
     *
     * If the cert does exist, then optionally test the key's use to see if it is valid for use as a transport key.
     * See {@link TransportCertValidationFilter#keyUse}
     *
     * @param jwkSet JWKSet to check
     * @param clientCertX5c String representing the JWK.x5c value we are expecting to matching.
     *                      NOTE: we are only testing the client cert portion of the x5c array, the first item in the array
     *                      and not the whole cert chain.
     * @return true if the cert exists in the JWK and has the correct keyUse
     */
    private boolean tlsClientCertExistsInJwkSet(JWKSet jwkSet, String clientCertX5c) {
        for (JWK jwk : jwkSet.getJWKsAsList()) {
            final List<String> x509Chain = jwk.getX509Chain();
            final String jwkX5c = x509Chain.get(0);
            if (isKeyUseValid(jwk) && clientCertX5c.equals(jwkX5c)) {
                logger.debug("Found matching tls cert for provided pem, with kid: " + jwk.getKeyId() + " x5t#S256: " + jwk.getX509ThumbprintS256());
                return true;
            }
        }
        logger.debug("tls transport cert does not match any certs registered in jwks for software statement");
        return false;
    }

    /**
     * Validates the JWK "use" value.
     *
     * @param jwk the JWK to validate
     * @return If keyUse field is not configured, then this always returns true.
     *         Otherwise, returns whether the JWK.use matches the keyUse field
     */
    private boolean isKeyUseValid(JWK jwk) {
        if (keyUse == null) {
            return true;
        }
        return keyUse.equals(jwk.getUse());
    }

    /**
     * Heaplet used to create {@link TransportCertValidationFilter} objects
     *
     * Mandatory fields:
     *  - clientTlsCertHeader: the name of the Request Header which contains the client's TLS cert
     *
     * Optional fields:
     *  - keyUse: the value to validate the JWK.use against, if this configuration is omitted then no validation is applied
     *  to this field. For Open Banking Directory this should be configured as "tls", which means the cert is a transport
     *  cert.
     *
     * Example config:
     * {
     *           "comment": "Validate the MTLS transport cert",
     *           "name": "TransportCertValidationFilter",
     *           "type": "TransportCertValidationFilter",
     *           "config": {
     *             "clientTlsCertHeader": "ssl-client-cert",
     *             "keyUse": "tls"
     *           }
     * }
     */
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final String clientCertHeaderName = config.get("clientTlsCertHeader").required().asString();
            // keyUse is optional config
            final String keyUse = config.get("keyUse").asString();
            final BiFunction<Context, Request, String> certificateSupplier = new CertificateFromHeaderSupplier(clientCertHeaderName);
            return new TransportCertValidationFilter(certificateSupplier, keyUse);
        }
    }
}
