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

import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.Client;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.idm.ApiClientService;
import com.forgerock.sapi.gateway.dcr.idm.IdmApiClientDecoder;
import com.forgerock.sapi.gateway.dcr.idm.IdmApiClientService;
import com.forgerock.sapi.gateway.fapi.FAPIUtils;
import com.forgerock.sapi.gateway.jwks.ApiClientJwkSetService;
import com.forgerock.sapi.gateway.jwks.DefaultApiClientJwkSetService;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

public class TokenEndpointTransportCertValidationFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final String accessTokenClientIdClaim = "aud";

    private final JwtReconstruction jwtReconstruction = new JwtReconstruction();

    private final CertificateResolver certificateResolver;

    private final ApiClientService apiClientService;

    private final TrustedDirectoryService trustedDirectoryService;

    private final ApiClientJwkSetService apiClientJwkSetService;

    private final TransportCertValidator transportCertValidator;

    public TokenEndpointTransportCertValidationFilter(ApiClientService apiClientService, TrustedDirectoryService trustedDirectoryService,
                                                      ApiClientJwkSetService apiClientJwkSetService, CertificateResolver certificateResolver,
                                                      TransportCertValidator transportCertValidator) {
        Reject.ifNull(apiClientService, "apiClientService must be provided");
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must be provided");
        Reject.ifNull(apiClientJwkSetService, "apiClientJwkSetService must be provided");
        Reject.ifNull(certificateResolver, "certificateResolver must be provided");
        Reject.ifNull(transportCertValidator, "transportCertValidator must be provided");
        this.apiClientService = apiClientService;
        this.trustedDirectoryService = trustedDirectoryService;
        this.apiClientJwkSetService = apiClientJwkSetService;
        this.certificateResolver = certificateResolver;
        this.transportCertValidator = transportCertValidator;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final String fapiInteractionIdForDisplay = FAPIUtils.getFapiInteractionIdForDisplay(context);
        final X509Certificate clientCertificate;
        try {
             clientCertificate = certificateResolver.resolveCertificate(context, request);
        } catch (CertificateException e) {
            logger.error("({}) Failed to resolve client mtls certificate", e);
            // TODO Review exceptions raised by the resolver and clean them up.
            return Promises.newResultPromise(TransportCertValidationFilter.createErrorResponse(e.getMessage()));
        }

        // Defer cert validation until the response path, then we know that the client authenticated successfully
        return next.handle(context, request).thenAsync(response -> {
            // Allow errors to pass on up the chain
            if (!response.getStatus().isSuccessful()) {
                return Promises.newResultPromise(response);
            } else {
                return response.getEntity().getJsonAsync()
                                           .then(this::getClientId)
                                           .thenAsync(apiClientService::getApiClient, e -> Promises.newExceptionPromise(new Exception(e)))
                                           .thenAsync(apiClient -> {
                        final TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(apiClient);
                        if (trustedDirectory == null) {
                            logger.error("({}) Failed to get trusted directory for apiClient: {}", fapiInteractionIdForDisplay, apiClient);
                            // TODO review
                            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                        }

                        return apiClientJwkSetService.getJwkSet(apiClient, trustedDirectory).then(jwkSet -> {
                            try {
                                transportCertValidator.validate(clientCertificate, jwkSet);
                            } catch (CertificateException ce) {
                                logger.error("({}) failed to validate that the supplied client certificate", ce);
                                // TODO Review exceptions raised by the resolver and clean them up.
                                return TransportCertValidationFilter.createErrorResponse(ce.getMessage());
                            }
                            // Successfully validated the client's cert, allow the original response to continue along the filter chain.
                            logger.debug("({}) transport cert validated successfully", fapiInteractionIdForDisplay);
                            return response;
                        }, ex -> {
                            logger.error("({}) Failed to get JWKS for ApiClient", fapiInteractionIdForDisplay, ex);
                            return new Response(Status.INTERNAL_SERVER_ERROR);
                        });
                    }, ex -> {
                        logger.error("({}) Failed to get ApiClient", fapiInteractionIdForDisplay, ex);
                        return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                    });
            }
        });
    }

    private String getClientId(Object jsonValue) {
        final JsonValue json = JsonValue.json(jsonValue);
        final JsonValue accessToken = json.get("access_token");
        if (accessToken == null || accessToken.isNull()) {
            throw new IllegalStateException("access_token is missing");
        }

        final SignedJwt accessTokenJwt = jwtReconstruction.reconstructJwt(accessToken.asString(), SignedJwt.class);
        final JsonValue clientId = accessTokenJwt.getClaimsSet().get(accessTokenClientIdClaim);
        if (clientId.isNull()) {
            throw new IllegalStateException("access_token claims missing required: " + accessTokenClientIdClaim + " claim");
        }
        return clientId.asString();
    }

    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final Handler clientHandler = config.get("clientHandler").as(requiredHeapObject(heap, Handler.class));
            final Client httpClient = new Client(clientHandler);

            String idmGetApiClientBaseUri = config.get("idmGetApiClientBaseUri").required().asString();
            if (!idmGetApiClientBaseUri.endsWith("/")) {
                idmGetApiClientBaseUri = idmGetApiClientBaseUri + '/';
            }

            final ApiClientService apiClientService = new IdmApiClientService(httpClient, idmGetApiClientBaseUri, new IdmApiClientDecoder());

            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));


            final JwkSetService jwkSetService = config.get("jwkSetService").as(requiredHeapObject(heap, JwkSetService.class));
            final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(jwkSetService);

            final TransportCertValidator transportCertValidator = config.get("transportCertValidator").required()
                    .as(requiredHeapObject(heap, TransportCertValidator.class));

            final String clientCertHeaderName = config.get("clientTlsCertHeader").required().asString();
            final CertificateResolver certResolver = new HeaderCertificateResolver(clientCertHeaderName);

            return new TokenEndpointTransportCertValidationFilter(apiClientService, trustedDirectoryService,
                                                                  apiClientJwkSetService, certResolver,
                                                                  transportCertValidator);

        }
    }
}
