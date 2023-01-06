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
package com.forgerock.sapi.gateway.dcr.request;

import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.io.IOException;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.ValidationException;
import com.forgerock.sapi.gateway.fapi.FAPIUtils;
import com.forgerock.sapi.gateway.fapi.v1.FAPIAdvancedDCRValidationFilter;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

public class RequestAndSsaSignatureValidationFilter implements Filter {

    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final Handler clientHandler = config.get("clientHandler").as(requiredHeapObject(heap, Handler.class));
            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));

            final List<String> supportedSigningAlgorithms = config.get("supportedSigningAlgorithms")
                    .as(evaluatedWithHeapProperties())
                    .defaultTo(DEFAULT_SUPPORTED_JWS_ALGORITHMS)
                    .asList(String.class);
            // Validate that if custom configuration was supplied, then that it is equal to or a subset of the values supported by the spec
            if (!DEFAULT_SUPPORTED_JWS_ALGORITHMS.containsAll(supportedSigningAlgorithms)) {
                throw new HeapException("supportedSigningAlgorithms config must be the same as (or a subset of): "
                        + DEFAULT_SUPPORTED_JWS_ALGORITHMS);
            }

            final RegistrationRequestObjectFromJwtSupplier registrationObjectSupplier = new RegistrationRequestObjectFromJwtSupplier(supportedSigningAlgorithms);
            final RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                    clientHandler, trustedDirectoryService,  registrationObjectSupplier);

            return filter;
        }
    }

    private static final Logger log = LoggerFactory.getLogger(RequestAndSsaSignatureValidationFilter.class);
    private final TrustedDirectoryService directorySvc;
    private final Handler handler;
    /**
     * The HTTP methods to apply validation to.
     * POST is used to create new OAuth2 client's and PUT updates existing OAuth2 clients, both of these types of
     * request must be validated.
     * DCR API also supports GET and DELETE, there is no validation to apply here so requests with these methods should
     * be passed on down the chain.
     */
    private static final Set<String> VALIDATABLE_HTTP_REQUEST_METHODS = Set.of("POST", "PUT");

    private static final List<String> DEFAULT_SUPPORTED_JWS_ALGORITHMS = Stream.of(JwsAlgorithm.PS256, JwsAlgorithm.ES256)
            .map(JwsAlgorithm::getJwaAlgorithmName)
            .collect(Collectors.toList());

    private final RegistrationRequestObjectFromJwtSupplier registrationRequestObjectFromJwtSupplier;


    private RequestAndSsaSignatureValidationFilter(Handler clientHandler,
            TrustedDirectoryService trustedDirectoryService,
            RegistrationRequestObjectFromJwtSupplier registrationRequestObjectFromJwtSupplier) {
        Reject.ifNull(clientHandler, "clientHandler must be provided");
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must be provided");
        Reject.ifNull(registrationRequestObjectFromJwtSupplier, "RegistrationRequestObjectFromJwtSupplier must be provided");
        this.directorySvc = trustedDirectoryService;
        this.handler = clientHandler;
        this.registrationRequestObjectFromJwtSupplier = registrationRequestObjectFromJwtSupplier;
        log.debug("RequestAndSsaSignatureValidationFilter constructed");
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final String fapiInteractionId = FAPIUtils.getFapiInteractionIdForDisplay(context);
        log.debug("({}) filtering - filtering out invalid signatures of registration request and ssa jwts",
                fapiInteractionId);
        if (!VALIDATABLE_HTTP_REQUEST_METHODS.contains(request.getMethod())) {
            return next.handle(context, request);
        }

        JsonValue registrationRequestObject = registrationRequestObjectFromJwtSupplier.apply(context, request);
        final String ssaJwt = registrationRequestObject.get("software_statement").asString();
        log.debug("{}ssa from registration request jwt is {}", ssaJwt);

        return next.handle(context, request);
    }



    /**
     * Supplies the Registration Request json object from a JWT contained within the Request.entity
     *
     * The JWT signing algo in the header is validated against the supported set of signing algorithms for FAPI.
     * No other validation is done at this point, it is assumed that Filters later in the chain will validate the sig etc
     */
    public static class RegistrationRequestObjectFromJwtSupplier implements BiFunction<Context, Request, JsonValue> {

        private final Set<String> supportedSigningAlgorithms;

        public RegistrationRequestObjectFromJwtSupplier(Collection<String> supportedSigningAlgorithms) {
            this.supportedSigningAlgorithms = new HashSet<>(supportedSigningAlgorithms);
        }

        @Override
        public JsonValue apply(Context context, Request request) {
            final String fapiInteractionId = FAPIUtils.getFapiInteractionIdForDisplay(context);
            try {
                final String registrationRequestJwtString = request.getEntity().getString();
                final SignedJwt registrationRequestJwt = new JwtReconstruction().reconstructJwt(registrationRequestJwtString,
                        SignedJwt.class);
                log.debug("({}) Registration Request JWT to validate: {}", fapiInteractionId, registrationRequestJwtString);
                final JwsAlgorithm signingAlgo = registrationRequestJwt.getHeader().getAlgorithm();
                // This validation is being done here as outside the supplier we are not aware that a JWT existed
                if (signingAlgo == null || !supportedSigningAlgorithms.contains(signingAlgo.getJwaAlgorithmName())) {
                    throw new ValidationException(ValidationException.ErrorCode.INVALID_CLIENT_METADATA,
                            "DCR request JWT signed must be signed with one of: " + supportedSigningAlgorithms);
                }
                final JwtClaimsSet claimsSet = registrationRequestJwt.getClaimsSet();
                return claimsSet.toJsonValue();
            } catch (InvalidJwtException | IOException e) {
                log.warn("(" + fapiInteractionId + ") FAPI DCR failed: unable to extract registration object JWT from request", e);
                // These are not validation errors, so do not raise a validation exception, instead allow the filter to handle the null response
                return null;
            }
        }
    }



}
