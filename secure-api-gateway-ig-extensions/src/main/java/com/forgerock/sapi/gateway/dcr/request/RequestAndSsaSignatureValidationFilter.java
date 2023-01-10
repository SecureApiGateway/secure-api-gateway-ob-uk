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
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SignatureException;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.validation.constraints.NotNull;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.jwk.JWKSet;
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
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

public class RequestAndSsaSignatureValidationFilter implements Filter {

    private final JwkSetService jwkSetService;
    private final JwtSignatureValidator jwtSignatureValidator;

    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final Handler clientHandler = config.get("clientHandler").as(requiredHeapObject(heap, Handler.class));
            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));

            final JwkSetService jwsSetService = config.get("jwkSetService")
                    .as(requiredHeapObject(heap, JwkSetService.class));

            final JwtSignatureValidator jwtSignatureValidator = config.get("jwtSignatureValidator")
                    .as(requiredHeapObject(heap, JwtSignatureValidator.class));

            final List<String> supportedSigningAlgorithms = config.get("supportedSigningAlgorithms")
                    .as(evaluatedWithHeapProperties())
                    .defaultTo(DEFAULT_SUPPORTED_JWS_ALGORITHMS)
                    .asList(String.class);
            // Validate that if custom configuration was supplied, then that it is equal to or a subset of the
            // values supported by the spec
            if (!DEFAULT_SUPPORTED_JWS_ALGORITHMS.containsAll(supportedSigningAlgorithms)) {
                throw new HeapException("supportedSigningAlgorithms config must be the same as (or a subset of): "
                        + DEFAULT_SUPPORTED_JWS_ALGORITHMS);
            }

            final RegistrationRequestObjectFromJwtSupplier registrationObjectSupplier =
                    new RegistrationRequestObjectFromJwtSupplier();
            final RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                    clientHandler, trustedDirectoryService,  registrationObjectSupplier, supportedSigningAlgorithms,
                    jwsSetService, jwtSignatureValidator);

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

    private static final List<String> DEFAULT_SUPPORTED_JWS_ALGORITHMS = Stream.of(JwsAlgorithm.PS256,
                    JwsAlgorithm.ES256)
            .map(JwsAlgorithm::getJwaAlgorithmName)
            .collect(Collectors.toList());

    private final RegistrationRequestObjectFromJwtSupplier registrationRequestObjectFromJwtSupplier;

    private final Collection<String> supportedSigningAlgorithms;


    RequestAndSsaSignatureValidationFilter(Handler clientHandler,
            TrustedDirectoryService trustedDirectoryService,
            RegistrationRequestObjectFromJwtSupplier registrationRequestObjectFromJwtSupplier,
            Collection<String> supportedSigningAlgorithms, JwkSetService jwkSetService,
            JwtSignatureValidator jwtSignatureValidator) {
        Reject.ifNull(clientHandler, "clientHandler must be provided");
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must be provided");
        Reject.ifNull(registrationRequestObjectFromJwtSupplier, "RegistrationRequestObjectFromJwtSupplier " +
                "must be provided");
        Reject.ifNull(supportedSigningAlgorithms, "supportedSigningAlgorithms must be provided");
        Reject.ifNull(jwkSetService, "jwkSetService must be provided");
        Reject.ifNull(jwtSignatureValidator, "jwtSignatureValidator must be provided");
        this.directorySvc = trustedDirectoryService;
        this.handler = clientHandler;
        this.registrationRequestObjectFromJwtSupplier = registrationRequestObjectFromJwtSupplier;
        this.supportedSigningAlgorithms = supportedSigningAlgorithms;
        this.jwkSetService = jwkSetService;
        this.jwtSignatureValidator = jwtSignatureValidator;
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

        SignedJwt registrationRequestJwt = getRegistrationRequestObjectOrThrow(fapiInteractionId, context, request);
        checkJwtSigningAlgorithmIsValid(fapiInteractionId, registrationRequestJwt, supportedSigningAlgorithms);
        final JwtClaimsSet registrationRequestJwtClaimsSet = registrationRequestJwt.getClaimsSet();

        final String ssaJwtString = getSsaEncodedJwtString(fapiInteractionId, registrationRequestJwtClaimsSet);
        log.debug("({}) ssa from registration request jwt is {}", fapiInteractionId, ssaJwtString);
        SignedJwt ssaSignedJwt = getSignedJwt(fapiInteractionId, ssaJwtString, supportedSigningAlgorithms);

        final JwtClaimsSet ssaClaimsSet = ssaSignedJwt.getClaimsSet();
        String ssaIssuer = getSsaIssuer(fapiInteractionId, ssaClaimsSet);
        TrustedDirectory ssaIssuingDirectory = getSsaTrustedDirectory(fapiInteractionId, ssaIssuer);

        // Validate the SSA!
        validateSsaJwtSignature(fapiInteractionId, ssaIssuingDirectory, ssaSignedJwt);

        if(ssaIssuingDirectory.softwareStatementHoldsJwksUri()){
            validateRegistrationRequestJwtSignature(fapiInteractionId, ssaIssuingDirectory, ssaClaimsSet,
                    registrationRequestJwt);
        } else {
            // ToDo - validate if JWKS is in the software statement rather than being obtainable from a URI
        }
        log.info("({}) The SSA and the registration JWS both have valid signatures", fapiInteractionId);
        return next.handle(context, request);
    }

    @NotNull
    private TrustedDirectory getSsaTrustedDirectory(String fapiInteractionId, String ssaIssuer) {
        TrustedDirectory ssaIssuingDirectory = directorySvc.getTrustedDirectoryConfiguration(ssaIssuer);
        if(ssaIssuingDirectory == null){
            String errorDescription = "SSA was not issued by a Trusted Directory";
            log.debug("({}) {}" , fapiInteractionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.UNAPPROVED_SOFTWARE_STATEMENT,
                    errorDescription);
        }
        return ssaIssuingDirectory;
    }

    @NotNull
    private String getSsaIssuer(String transactionId, JwtClaimsSet ssaClaimsSet){
        String ssaIssuer = ssaClaimsSet.getIssuer();
        if(ssaIssuer == null || ssaIssuer.isBlank()){
            String errorDescription = "registration request's 'software_statement' jwt must contain an issuer claim";
            log.debug("({}) {}", transactionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }
        log.debug("{}SSA jwt issuer is '{}'", transactionId, ssaIssuer);
        return ssaIssuer;
    }

    private void validateRegistrationRequestJwtSignature(String fapiInteractionId, TrustedDirectory ssaIssuingDirectory,
            JwtClaimsSet ssaClaimsSet, SignedJwt registrationReqeustJwt){
        String jwksUriClaimName = ssaIssuingDirectory.getSoftwareStatementJwksUriClaimName();
        String jwksUri = ssaClaimsSet.getClaim(jwksUriClaimName, String.class);
        if(jwksUri == null || jwksUri.isBlank()){
            String errorDescription = "Could not obtain jwks_uri from the registration request's " +
                    "software_statement jws";
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT,
                    errorDescription);
        }

        URL softwareStatementsJwksUri;
        try {
            softwareStatementsJwksUri = new URL(jwksUri);
            if (!"https".equals(softwareStatementsJwksUri.getProtocol())) {
                String errorDescription = "registration request's software_statement jwt '" + jwksUriClaimName +
                        "' must contain an HTTPS URI";
                log.debug("({}) {}", fapiInteractionId, errorDescription);
                throw new ValidationException(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT,
                        errorDescription);
            }
        } catch (MalformedURLException e) {
            String errorDescription = "The registration request jwt signature could not be validated. The '" +
                    jwksUriClaimName + "' claim in the software statement has a value of '" + jwksUri + "' this " +
                    "value must be a valid URL";
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }

        try{
            validateJwsUsingJwksUri(fapiInteractionId, softwareStatementsJwksUri, registrationReqeustJwt);
        } catch (SignatureException e) {
            String errorDescription = "Failed to validate registration request against jwks_uri '" +
                    softwareStatementsJwksUri + "'";
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.INVALID_CLIENT_METADATA, errorDescription);
        }
    }

    private void validateSsaJwtSignature(@NotNull String fapiInteractionId,
            @NotNull TrustedDirectory ssaIssuingDirectory,
            @NotNull SignedJwt ssaSignedJwt){
        String jwksUri = ssaIssuingDirectory.getDirectoryJwksUri();
        try {
            URL jwksUrl = new URL(jwksUri);
            validateJwsUsingJwksUri(fapiInteractionId, jwksUrl, ssaSignedJwt);
        } catch (SignatureException e) {
            String errorDescription = "Failed to validate SSA against jwks_uri '" + jwksUri + "'";
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        } catch (MalformedURLException e) {
            String errorDescription = "The value of the '" + ssaIssuingDirectory.getIssuer() + "' Trusted Directory" +
                    " JWKS Uri must be a valid URI";
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }
    }

    private void validateJwsUsingJwksUri(String transactionId, URL jwksToValidateSsaAgainst,
            SignedJwt registrationRequestJwt) throws SignatureException {
        try {
            JWKSet jwkSet = this.jwkSetService.getJwkSet(jwksToValidateSsaAgainst).get();
            this.jwtSignatureValidator.validateSignature(registrationRequestJwt, jwkSet);
        } catch (InterruptedException | ExecutionException e) {
            String errorDescription = "Promise was cancelled or did not complete successfully";
            log.warn("({}) {}", transactionId, errorDescription, e);
            throw new RuntimeException(e);
        }
    }

    @NotNull
    private SignedJwt getSignedJwt(String fapiInteractionId, String b64EncodedJwtString,
            Collection<String> supportedSigningAlgorithms) {
        final SignedJwt ssaJwt = new JwtReconstruction().reconstructJwt(b64EncodedJwtString, SignedJwt.class);
        checkJwtSigningAlgorithmIsValid(fapiInteractionId, ssaJwt, supportedSigningAlgorithms);
        return ssaJwt;
    }


    @NotNull
    private String getSsaEncodedJwtString(@NotNull String fapiInteractionId,
            @NotNull JwtClaimsSet registrationRequestJwtClaimsSet){
        final String ssaJwtString = registrationRequestJwtClaimsSet.getClaim("software_statement", String.class);
        if(ssaJwtString == null || ssaJwtString.isBlank()){
            String errorDescription = "registration request jwt must contain 'software_statement claim";
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.INVALID_CLIENT_METADATA, errorDescription);
        }
        return ssaJwtString;
    }

    private void checkJwtSigningAlgorithmIsValid(String fapiInteractionId, SignedJwt jwt,
            Collection<String> supportedSigningAlgorithms){
        final JwsAlgorithm jwtSigningAlgorithm = jwt.getHeader().getAlgorithm();
        if (jwtSigningAlgorithm == null ||
                !supportedSigningAlgorithms.contains(jwtSigningAlgorithm.getJwaAlgorithmName())) {
            String errorDescription = "DCR request JWT signed must be signed with one of: " +
                    supportedSigningAlgorithms;
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.INVALID_CLIENT_METADATA, errorDescription);
        }
    }

    /**
     * Get the Registration Request jwt from the {@code Request}
     * @param fapiInteractionId the value of the x-fapi-interaction-id from the context
     * @param context the request context
     * @param request the request
     * @return a String containing the encoded jwt string or if no request
     */
    private SignedJwt getRegistrationRequestObjectOrThrow(String fapiInteractionId, Context context, Request request){
        SignedJwt registrationRequestJwt = registrationRequestObjectFromJwtSupplier.apply(context, request);
        if(registrationRequestJwt == null){
            String errorDescription = "Requests to registration endpoint must contain a signed request jwt";
            log.debug("({}) {}", fapiInteractionId, errorDescription);
            throw new ValidationException(ValidationException.ErrorCode.INVALID_CLIENT_METADATA,
                    errorDescription);
        }
        return registrationRequestJwt;
    }

    /**
     * Supplies the Registration Request json object from a JWT contained within the Request.entity
     *
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
