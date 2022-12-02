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
package com.forgerock.sapi.gateway.dcr.fapi.v1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.ValidationException;
import com.forgerock.sapi.gateway.dcr.ValidationException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.Validator;
import com.forgerock.sapi.gateway.dcr.ErrorResponseFactory;
import com.forgerock.sapi.gateway.fapi.FAPIUtils;

/**
 * Filter which implements the "Financial-grade API Security Profile 1.0 - Part 2: Advanced" spec validations
 * required for DCR (Dynamic Client Registration), see: https://openid.net/specs/openid-financial-api-part-2-1_0.html
 *
 * This filter should sit in front of filter(s) which implement DCR for a particular API.
 *
 * This filter will reject any requests which would result in an OAuth2 client being created which did not conform to
 * the FAPI spec.
 *
 * The {@link Heaplet} is used to construct this filter, see its documentation for the configuration options.
 */
public class FAPIAdvancedDCRValidationFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(FAPIAdvancedDCRValidationFilter.class);

    private static final List<String> RESPONSE_TYPE_CODE = List.of("code");
    private static final List<String> RESPONSE_TYPE_CODE_ID_TOKEN = List.of("code id_token");

    private static final List<String> DEFAULT_SUPPORTED_JWS_ALGORITHMS = Stream.of(JwsAlgorithm.PS256, JwsAlgorithm.ES256)
                                                                               .map(JwsAlgorithm::getJwaAlgorithmName)
                                                                               .collect(Collectors.toList());

    private static final List<String> DEFAULT_SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS = List.of("tls_client_auth",
                                                                                              "self_signed_tls_client_auth",
                                                                                              "private_key_jwt");

    private static final List<String> DEFAULT_REG_OBJ_SIGNING_FIELD_NAMES = List.of("token_endpoint_auth_signing_alg",
                                                                                    "id_token_signed_response_alg",
                                                                                    "request_object_signing_alg");
    private Set<String> supportedSigningAlgorithms;

    private Set<String> supportedTokenEndpointAuthMethods;

    private Collection<String> registrationObjectSigningFieldNames;

    /**
     * Function which returns a PEM encoded x509 certificate as a String.
     */
    private BiFunction<Context, Request, String> certificateSupplier;

    /**
     * Function which validates a PEM encoded x509 certificate String
     */
    private Validator<String> certificateValidator;

    /**
     * Function which returns the DCR Registration Request json object.
     *
     * NOTE: If a JWT is submitted which contains the DCR Registration Request as claims, then those claims should
     * be extracted from the JWT and returned. This function provides flexibility, allowing the registration request
     * to be sourced directly or unwrapped from within a JWT.
     */
    private BiFunction<Context, Request, JsonValue> registrationObjectSupplier;

    /**
     * List of Validators which will validate the DCR Registration json object
     */
    private List<Validator<JsonValue>> requestObjectValidators;

    private final ErrorResponseFactory errorResponseFactory;

    /**
     * The filter should be constructed using the {@link Heaplet}.
     * This object is complex to create, the Heaplet follows the builder pattern to produce a coherent object.
     */
    private FAPIAdvancedDCRValidationFilter() {
        errorResponseFactory = new ErrorResponseFactory();
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        try {
            certificateValidator.validate(certificateSupplier.apply(context, request));

            final JsonValue registrationObject = registrationObjectSupplier.apply(context, request);
            if (registrationObject == null) {
                throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "registration request entity is missing or malformed");
            }
            validateRegistrationRequestObject(registrationObject);
        } catch (ValidationException ve) {
            return Promises.newResultPromise(errorResponseFactory.errorResponse(context, ve));
        }
        return next.handle(context, request);
    }

    void validateRegistrationRequestObject(JsonValue registrationObject) {
        for (Validator<JsonValue> validator : requestObjectValidators) {
            validator.validate(registrationObject);
        }
    }

    void validateRedirectUris(JsonValue registrationObject) {
        final List<String> redirectUris = registrationObject.get("redirect_uris").asList(String.class);
        if (redirectUris == null) {
            throw new ValidationException(ErrorCode.INVALID_REDIRECT_URI, "request object must contain redirect_uris field");
        }
        if (redirectUris.isEmpty()) {
            throw new ValidationException(ErrorCode.INVALID_REDIRECT_URI, "redirect_uris array must not be empty");
        }
        for (String uriString : redirectUris) {
            final URI redirectUri;
            try {
                redirectUri = new URI(uriString);
            } catch (URISyntaxException ex) {
                throw new ValidationException(ErrorCode.INVALID_REDIRECT_URI, "redirect_uri: " + uriString + " is not a valid URI");
            }
            if (!"https".equals(redirectUri.getScheme())) {
                throw new ValidationException(ErrorCode.INVALID_REDIRECT_URI, "redirect_uris must use https scheme");
            }
        }
    }

    void validateResponseTypes(JsonValue registrationObject) {
        final List<String> responseTypes = registrationObject.get("response_types").asList(String.class);
        if (responseTypes == null || responseTypes.isEmpty()) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: response_types");
        }
        if (responseTypes.equals(RESPONSE_TYPE_CODE)) {
            validateResponseTypeCode(registrationObject);
        } else if (!responseTypes.equals(RESPONSE_TYPE_CODE_ID_TOKEN)) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "response_types not supported, must be one of: "
                    + List.of(RESPONSE_TYPE_CODE, RESPONSE_TYPE_CODE_ID_TOKEN));
        }
    }

    private void validateResponseTypeCode(JsonValue registrationObject) {
        final String responseMode = registrationObject.get("response_mode").asString();
        if (responseMode == null) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA,
                    "request object must contain field: response_mode when response_types is: " + RESPONSE_TYPE_CODE);
        }
        final List<String> validResponseModesForResponseTypeCode = List.of("jwt");
        if (!validResponseModesForResponseTypeCode.contains(responseMode)) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "response_mode not supported, must be one of: "
                    + validResponseModesForResponseTypeCode);
        }
    }

    void validateTokenEndpointAuthMethods(JsonValue registrationObject) {
        final String tokenEndpointAuthMethod = registrationObject.get("token_endpoint_auth_method").asString();
        if (tokenEndpointAuthMethod == null) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: token_endpoint_auth_method");
        }
        if (!supportedTokenEndpointAuthMethods.contains(tokenEndpointAuthMethod)) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "token_endpoint_auth_method not supported, must be one of: "
                    + supportedTokenEndpointAuthMethods.stream().sorted().collect(Collectors.toList()));
        }
    }

    void validateSigningAlgorithmUsed(JsonValue registrationObject) {
        for (String signingFieldName : registrationObjectSigningFieldNames) {
            final String signingAlg = registrationObject.get(signingFieldName).asString();
            if (signingAlg == null) {
                throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: "
                        + signingFieldName);
            }
            if (!supportedSigningAlgorithms.contains(signingAlg)) {
                throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "request object field: " + signingFieldName
                        + ", must be one of: " + supportedSigningAlgorithms);
            }
        }
    }

    void setSupportedSigningAlgorithms(Collection<String> supportedSigningAlgorithms) {
        this.supportedSigningAlgorithms = new HashSet<>(supportedSigningAlgorithms);
    }

    void setSupportedTokenEndpointAuthMethods(Collection<String> supportedTokenEndpointAuthMethods) {
        this.supportedTokenEndpointAuthMethods = new HashSet<>(supportedTokenEndpointAuthMethods);
    }

    void setRegistrationObjectSigningFieldNames(Collection<String> registrationObjectSigningFieldNames) {
        this.registrationObjectSigningFieldNames = registrationObjectSigningFieldNames;
    }

    void setCertificateSupplier(BiFunction<Context, Request, String> certificateSupplier) {
        this.certificateSupplier = certificateSupplier;
    }

    void setCertificateValidator(Validator<String> certificateValidator) {
        this.certificateValidator = certificateValidator;
    }

    void setRegistrationObjectSupplier(BiFunction<Context, Request, JsonValue> registrationObjectSupplier) {
        this.registrationObjectSupplier = registrationObjectSupplier;
    }

    void setRequestObjectValidators(List<Validator<JsonValue>>  requestObjectValidators) {
        this.requestObjectValidators = requestObjectValidators;
    }

    /**
     * When configuring the requestObjectValidators (via the setter), callers can extend the validation rules applied by
     * first calling this method and then appending additional validators to the collection.
     *
     * @return list of validators that apply the default validation rules to the request object as per the spec.
     */
    public List<Validator<JsonValue>> getDefaultRequestObjectValidators() {
        return List.of(this::validateRedirectUris, this::validateResponseTypes, this::validateSigningAlgorithmUsed,
                       this::validateTokenEndpointAuthMethods);
    }

    /**
     * Supplier which returns a certificate String as sourced from a Request Header.
     */
    public static class CertificateFromHeaderSupplier implements BiFunction<Context, Request, String> {

        private final String certificateHeaderName;

        public CertificateFromHeaderSupplier(String certificateHeaderName) {
            this.certificateHeaderName = Reject.checkNotBlank(certificateHeaderName);
        }

        @Override
        public String apply(Context context, Request request) {
            final String headerValue = request.getHeaders().getFirst(certificateHeaderName);
            if (headerValue == null) {
                return null;
            }
            return URLDecoder.decode(headerValue, StandardCharsets.UTF_8);
        }
    }

    /**
     * Default implementation of the ClientCertificateValidator.
     * This function takes a pem encoded certificate String and validates it.
     */
    public static class DefaultClientCertificateValidator implements Validator<String> {
        @Override
        public void validate(String certPem) {
            if (certPem == null) {
                throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate must be supplied");
            }
            LOGGER.debug("Parsing cert: {}", certPem);
            final InputStream certStream = new ByteArrayInputStream(certPem.getBytes());
            try {
                final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                final Certificate certificate = certificateFactory.generateCertificate(certStream);
            } catch (CertificateException e) {
                LOGGER.warn("FAPI DCR failed due to invalid cert", e);
                throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate PEM supplied is invalid");
            }
        }
    }

    /**
     * Supplies the Registration Request json object from a JWT contained within the Request.entity
     *
     * The JWT signing algo in the header is validated against the supported set of signing algorithms for FAPI.
     * No other validation is done at this point, it is assumed that Filters later in the chain will validate the sig etc
     */
    public static class RegistrationObjectFromEntityJWTSupplier implements BiFunction<Context, Request, JsonValue> {

        private final Set<String> supportedSigningAlgorithms;

        public RegistrationObjectFromEntityJWTSupplier(Collection<String> supportedSigningAlgorithms) {
            this.supportedSigningAlgorithms = new HashSet<>(supportedSigningAlgorithms);
        }

        @Override
        public JsonValue apply(Context context, Request request) {
            try {
                final SignedJwt signedJwt = new JwtReconstruction().reconstructJwt(request.getEntity().getString(),
                                                                                   SignedJwt.class);
                final JwsAlgorithm signingAlgo = signedJwt.getHeader().getAlgorithm();
                // This validation is being done here as outside the supplier we are not aware that a JWT existed
                if (signingAlgo == null || !supportedSigningAlgorithms.contains(signingAlgo.getJwaAlgorithmName())) {
                    throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA,
                            "DCR request JWT signed must be signed with one of: " + supportedSigningAlgorithms);
                }
                final JwtClaimsSet claimsSet = signedJwt.getClaimsSet();
                return claimsSet.toJsonValue();
            } catch (InvalidJwtException | IOException e) {
                final String fapiInteractionId = FAPIUtils.getFapiInteractionIdForDisplay(context);
                LOGGER.warn("(" + fapiInteractionId + ") FAPI DCR failed: unable to extract registration object JWT from request", e);
                // These are not validation errors, so do not raise a validation exception, instead allow the filter to handle the null response
                return null;
            }
        }
    }

    // TODO document config
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {

            final FAPIAdvancedDCRValidationFilter filter = new FAPIAdvancedDCRValidationFilter();

            // TODO validate any custom conf is sane, i.e. for signing algs, should be a subset of the DEFAULT.
            final List<String> supportedSigningAlgorithms = config.get("supportedSigningAlgorithms")
                                                                   .as(evaluatedWithHeapProperties())
                                                                   .defaultTo(DEFAULT_SUPPORTED_JWS_ALGORITHMS)
                                                                   .asList(String.class);
            filter.setSupportedSigningAlgorithms(supportedSigningAlgorithms);

            // TODO validate any custom config is sane, should be a subset of the DEFAULT
            filter.setSupportedTokenEndpointAuthMethods(config.get("supportedTokenEndpointAuthMethods")
                                                              .as(evaluatedWithHeapProperties())
                                                              .defaultTo(DEFAULT_SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS)
                                                              .asList(String.class));

            filter.setRegistrationObjectSigningFieldNames(config.get("registrationObjectSigningFieldNames")
                                                                .as(evaluatedWithHeapProperties())
                                                                .defaultTo(DEFAULT_REG_OBJ_SIGNING_FIELD_NAMES)
                                                                .asList(String.class));

            final Validator<String> certificateValidator = new DefaultClientCertificateValidator();
            filter.setCertificateValidator(certificateValidator);

            final String clientCertHeaderName = config.get("certificateHeader").required().asString();
            final BiFunction<Context, Request, String> certificateSupplier = new CertificateFromHeaderSupplier(clientCertHeaderName);
            filter.setCertificateSupplier(certificateSupplier);

            final List<Validator<JsonValue>> requestObjectValidators = filter.getDefaultRequestObjectValidators();
            filter.setRequestObjectValidators(requestObjectValidators);

            final BiFunction<Context, Request, JsonValue> registrationObjectSupplier = new RegistrationObjectFromEntityJWTSupplier(supportedSigningAlgorithms);
            filter.setRegistrationObjectSupplier(registrationObjectSupplier);

            return filter;
        }
    }
}
