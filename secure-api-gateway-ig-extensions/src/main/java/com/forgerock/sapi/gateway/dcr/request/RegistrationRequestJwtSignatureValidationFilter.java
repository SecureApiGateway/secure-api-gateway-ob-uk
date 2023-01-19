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

import org.apache.ivy.util.StringUtils;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
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

import com.forgerock.sapi.gateway.dcr.request.DCRSignatureValidationException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.utils.DCRUtils;
import com.forgerock.sapi.gateway.dcr.utils.JwtReconstructionException;
import com.forgerock.sapi.gateway.fapi.FAPIUtils;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

public class RegistrationRequestJwtSignatureValidationFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestJwtSignatureValidationFilter.class);
    /**
     * The HTTP methods to apply validation to.
     * POST is used to create new OAuth2 client's and PUT updates existing OAuth2 clients, both of these types of
     * request must be validated.
     * DCR API also supports GET and DELETE, there is no validation to apply here so requests with these methods should
     * be passed on down the chain.
     */
    private static final Set<String> VALIDATABLE_HTTP_REQUEST_METHODS = Set.of("POST", "PUT");
    private static final List<String> DEFAULT_SUPPORTED_JWS_ALGORITHMS = Stream.of(JwsAlgorithm.PS256,
                    JwsAlgorithm.ES256)
            .map(JwsAlgorithm::getJwaAlgorithmName)
            .collect(Collectors.toList());
    private final RegistrationRequestObjectFromJwtSupplier registrationRequestObjectFromJwtSupplier;
    private final Collection<String> supportedSigningAlgorithms;
    private final SoftwareStatementAssertionSignatureValidatorService ssaValidator;
    private final RegistrationRequestJwtSignatureValidationService registrationRequestJwtValidator;
    private final DCRUtils dcrUtils;

    /**
     * Constructor
     * @param registrationRequestObjectFromJwtSupplier obtains the registration request object from the request
     * @param supportedSigningAlgorithms a {@code Collection} containing the valid signing algorithms that jwts may be
     *                                   signed with
     * @param dcrUtils utility class containing common methods
     * @param ssaValidator a service used to validate the SSA signature
     * @param registrationRequestJwtValidator used to validate the registration request jwt signature
     */
    RegistrationRequestJwtSignatureValidationFilter(
            RegistrationRequestObjectFromJwtSupplier registrationRequestObjectFromJwtSupplier,
            Collection<String> supportedSigningAlgorithms,
            DCRUtils dcrUtils,
            SoftwareStatementAssertionSignatureValidatorService ssaValidator,
            RegistrationRequestJwtSignatureValidationService registrationRequestJwtValidator) {
        Reject.ifNull(registrationRequestObjectFromJwtSupplier, "RegistrationRequestObjectFromJwtSupplier " +
                "must be provided");
        Reject.ifNull(supportedSigningAlgorithms, "supportedSigningAlgorithms must be provided");
        Reject.ifNull(dcrUtils, "dcrUtils must be provided");
        Reject.ifNull(ssaValidator, "ssaValidator must be provided");
        Reject.ifNull(registrationRequestJwtValidator, "registrationRequestJwtValidator must be provided");
        this.registrationRequestObjectFromJwtSupplier = registrationRequestObjectFromJwtSupplier;
        this.supportedSigningAlgorithms = supportedSigningAlgorithms;
        this.ssaValidator = ssaValidator;
        this.registrationRequestJwtValidator = registrationRequestJwtValidator;
        this.dcrUtils = dcrUtils;
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

        try {
            SignedJwt registrationRequestJwt = getRegistrationRequestObjectOrThrow(fapiInteractionId, context, request);
            checkJwtSigningAlgorithmIsValid(fapiInteractionId, registrationRequestJwt, supportedSigningAlgorithms);
            final JwtClaimsSet registrationRequestJwtClaimsSet = registrationRequestJwt.getClaimsSet();

            final String ssaJwtString = getSsaB64EncodedJwtString(fapiInteractionId, registrationRequestJwtClaimsSet);
            log.debug("({}) ssa from registration request jwt is {}", fapiInteractionId, ssaJwtString);
            SignedJwt ssaSignedJwt = getSoftwareStatementAssertionSignedJwt(fapiInteractionId, ssaJwtString,
                    supportedSigningAlgorithms);
            final JwtClaimsSet ssaClaimsSet = ssaSignedJwt.getClaimsSet();

            Promise<Response, DCRSignatureValidationException> ssaValidationPromise =
                    ssaValidator.validateSoftwareStatementAssertionSignature(fapiInteractionId, ssaSignedJwt);

            return ssaValidationPromise.thenAsync( response ->
                registrationRequestJwtValidator.validateRegistrationRequestJwtSignature(fapiInteractionId, ssaClaimsSet,
                                registrationRequestJwt).thenAsync(
                    regRequestValidationResponse -> {
                        if (regRequestValidationResponse.getStatus() != Status.OK) {
                            log.info("({}) Response from validation is not OK as expected. Resposne: {}",
                                    fapiInteractionId, regRequestValidationResponse);
                            return Promises.newResultPromise(response);
                        }
                        log.debug("({}) Registration Request and embedded SSA both have valid signatures",
                                fapiInteractionId);
                        return next.handle(context, request);
                    }, ex -> {
                        log.info("({}) Registration Request validation failed: {}", fapiInteractionId,
                                ex.getMessage(), ex);
                        Response badRequest = new Response(Status.BAD_REQUEST).setEntity(getJsonResponseBody(ex));
                        return Promises.newResultPromise(badRequest);
                    }, rte -> {
                        log.info("({}) A Runtime Exception occurred while validating the Registration Response Jwt " +
                                "signature: {}", fapiInteractionId, "error: " + rte.getMessage(), rte);
                        return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                    }
                ), ex -> {
                    log.info("({}) Software Statement validation failed:  {}", fapiInteractionId, ex.getMessage(),
                            ex);
                    Response badRequest = new Response(Status.BAD_REQUEST).setEntity(getJsonResponseBody(ex));
                    return Promises.newResultPromise(badRequest);
                }, rte -> {
                    log.error("({}) Runtime Error while validating Registration Request: {}", fapiInteractionId,
                            "error: " + rte.getMessage(), rte);
                    return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                });
        } catch (DCRSignatureValidationException e) {
            String responseBody = getJsonResponseBody(e);
            return Promises.newResultPromise(new Response(Status.BAD_REQUEST).setEntity(responseBody));
        }
    }

    private String getJsonResponseBody(DCRSignatureValidationException ex) {
        return "{\"error_code\":\"" + ex.getErrorCode() + "\"," +
                "\"error_description\":\"" + ex.getErrorDescription() + "\"}";
    }


    private SignedJwt getSoftwareStatementAssertionSignedJwt(String fapiInteractionId, String b64EncodedJwtString,
            Collection<String> supportedSigningAlgorithms) throws DCRSignatureValidationException {
        final SignedJwt ssaJwt;
        try {
            ssaJwt = dcrUtils.getSignedJwt(b64EncodedJwtString);
            checkJwtSigningAlgorithmIsValid(fapiInteractionId, ssaJwt, supportedSigningAlgorithms);
            return ssaJwt;
        } catch (JwtReconstructionException e) {
            String errorDescription = "Badly formed b64 encoded software statement in registration request";
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new DCRSignatureValidationException(ErrorCode.INVALID_CLIENT_METADATA, errorDescription);
        }
    }

    /**
     * get the b64 encoded jwt string from the 'software_statement' claim of the registration request jwt
     * @param transactionId used for logging purposes
     * @param registrationRequestJwtClaimsSet the registration request jwt claims set
     * @return the software statement assertion claim value b64 Encoded Jwt String
     * @throws DCRSignatureValidationException
     */
    private String getSsaB64EncodedJwtString(String transactionId, JwtClaimsSet registrationRequestJwtClaimsSet)
            throws DCRSignatureValidationException {
        final String ssaJwtString = registrationRequestJwtClaimsSet.getClaim("software_statement", String.class);
        if (StringUtils.isNullOrEmpty(ssaJwtString)) {
            String errorDescription = "registration request jwt must contain 'software_statement' claim";
            log.debug("({}) {}", transactionId, errorDescription);
            throw new DCRSignatureValidationException(ErrorCode.INVALID_CLIENT_METADATA, errorDescription);
        }
        return ssaJwtString;
    }

    /**
     * Check that the signing algorithm specified in the signed jwt is one of the allowed algorithms
     * @param transactionId used for logging purposes
     * @param signedJwt
     * @param supportedSigningAlgorithms
     * @throws DCRSignatureValidationException
     */
    private void checkJwtSigningAlgorithmIsValid(String transactionId, SignedJwt signedJwt,
            Collection<String> supportedSigningAlgorithms) throws DCRSignatureValidationException {
        final JwsAlgorithm jwtSigningAlgorithm = signedJwt.getHeader().getAlgorithm();
        if (jwtSigningAlgorithm == null ||
                !supportedSigningAlgorithms.contains(jwtSigningAlgorithm.getJwaAlgorithmName())) {
            String errorDescription = "DCR request JWT must be signed with one of: " +
                    supportedSigningAlgorithms;
            log.debug("({}) {}", transactionId, errorDescription);
            throw new DCRSignatureValidationException(ErrorCode.INVALID_CLIENT_METADATA, errorDescription);
        }
    }

    /**
     * Get the Registration Request jwt from the {@code Request}
     *
     * @param fapiInteractionId the value of the x-fapi-interaction-id from the context
     * @param context           the request context
     * @param request           the request
     * @return a String containing the encoded jwt string or if no request
     */
    private SignedJwt getRegistrationRequestObjectOrThrow(String fapiInteractionId, Context context, Request request)
            throws DCRSignatureValidationException {
        SignedJwt registrationRequestJwt = registrationRequestObjectFromJwtSupplier.apply(context, request);
        if (registrationRequestJwt == null) {
            String errorDescription = "Requests to registration endpoint must contain a signed request jwt";
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new DCRSignatureValidationException(ErrorCode.INVALID_CLIENT_METADATA,
                    errorDescription);
        }
        return registrationRequestJwt;
    }


    /**
     * Heaplet is used to get arguments from the IG config and create a RequestAndSsaSignatureValidationFilter
     * on the IG heap.
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));

            final JwkSetService jwtSetService = config.get("jwkSetService")
                    .as(requiredHeapObject(heap, JwkSetService.class));

            final JwtSignatureValidator jwtSignatureValidator = config.get("jwtSignatureValidator")
                    .as(requiredHeapObject(heap, JwtSignatureValidator.class));

            final List<String> configurationSigningAlgorithms = config.get("configurationSigningAlgorithms")
                    .as(evaluatedWithHeapProperties())
                    .defaultTo(DEFAULT_SUPPORTED_JWS_ALGORITHMS)
                    .asList(String.class);

            if (!configuredSigningAlgorithmsAreSubsetOfSupportedAlgorithms(configurationSigningAlgorithms)) {
                throw new HeapException("configurationSigningAlgorithms config must be the same as (or a subset of): "
                        + DEFAULT_SUPPORTED_JWS_ALGORITHMS);
            }

            final RegistrationRequestObjectFromJwtSupplier registrationObjectSupplier =
                    new RegistrationRequestObjectFromJwtSupplier();

            final DCRUtils dcrUtils = new DCRUtils();

            final SoftwareStatementAssertionSignatureValidatorService ssaSignatureValidator
                    = new SoftwareStatementAssertionSignatureValidatorService(trustedDirectoryService,
                    jwtSetService, jwtSignatureValidator, dcrUtils);

            final RegistrationRequestJwtSignatureValidatorJwks regRequestJwksValidator =
                    new RegistrationRequestJwtSignatureValidatorJwks(jwtSignatureValidator);

            final RegistrationRequestJwtSignatureValidatorJwksUri regRequestJwksUriValidator =
                    new RegistrationRequestJwtSignatureValidatorJwksUri(jwtSetService, jwtSignatureValidator);

            final RegistrationRequestJwtSignatureValidationService registrationRequestValidator =
                    new RegistrationRequestJwtSignatureValidationService(
                            trustedDirectoryService, dcrUtils, regRequestJwksValidator, regRequestJwksUriValidator);

            return new RegistrationRequestJwtSignatureValidationFilter(
                    registrationObjectSupplier, configurationSigningAlgorithms, dcrUtils, ssaSignatureValidator,
                    registrationRequestValidator);
        }

        private boolean configuredSigningAlgorithmsAreSubsetOfSupportedAlgorithms(
                List<String> supportedSigningAlgorithms) {
            return new HashSet<>(DEFAULT_SUPPORTED_JWS_ALGORITHMS).containsAll(supportedSigningAlgorithms);
        }
    }

    /**
     * Supplies the Registration Request json object from a JWT contained within the Request.entity
     * <p>
     * The JWT signing algo in the header is validated against the supported set of signing algorithms for FAPI.
     * No other validation is done at this point, it is assumed that Filters later in the chain will validate the
     * sig etc
     */
    public static class RegistrationRequestObjectFromJwtSupplier implements BiFunction<Context, Request, SignedJwt> {

        public RegistrationRequestObjectFromJwtSupplier() {
        }

        @Override
        public SignedJwt apply(Context context, Request request) {
            final String fapiInteractionId = FAPIUtils.getFapiInteractionIdForDisplay(context);
            try {
                final String registrationRequestJwtString = request.getEntity().getString();
                log.debug("({}) Registration Request JWT to validate: {}", fapiInteractionId,
                        registrationRequestJwtString);
                final SignedJwt registrationRequestJwt = new JwtReconstruction().reconstructJwt(
                        registrationRequestJwtString, SignedJwt.class);

                return registrationRequestJwt;
            } catch (InvalidJwtException | IOException e) {
                log.warn("(" + fapiInteractionId + ") FAPI DCR failed: unable to extract registration object JWT from" +
                        " request", e);
                // These are not validation errors, so do not raise a validation exception, instead allow the filter
                // to handle the null response
                return null;
            }
        }
    }

}
