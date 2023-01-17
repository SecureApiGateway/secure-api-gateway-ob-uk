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

import java.net.MalformedURLException;
import java.net.URL;
import java.security.SignatureException;

import javax.validation.constraints.NotNull;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.request.DCRSignatureValidationException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.utils.DCRUtils;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

/**
 * Validates the Signature of the software statement jwt.
 */
public class DCRSsaSignatureValidator {

    private static final Logger log = LoggerFactory.getLogger(DCRSsaSignatureValidator.class);
    private final JwkSetService jwkSetService;
    private final JwtSignatureValidator jwtSignatureValidator;
    private final TrustedDirectoryService trustedDirectoryService;
    private final DCRUtils dcrUtils;


    /**
     * Constructs a DCRSsaValidator
     * @param trustedDirectoryService provides configuration relating to the directory that issued the Software
     *                                Statement Assertion.
     * @param jwkSetService obtains a JWK Set from a url (may provide caching)
     * @param jwtSignatureValidator validates the Software Statement Assertion's signature against a JWK Set
     * @param dcrUtils provides utility functions common to DCR related work
     */
    public DCRSsaSignatureValidator(TrustedDirectoryService trustedDirectoryService, JwkSetService jwkSetService,
            JwtSignatureValidator jwtSignatureValidator, DCRUtils dcrUtils) {
        Reject.ifNull(jwkSetService, "jwkSetService must be provided");
        Reject.ifNull(jwtSignatureValidator, "jwtSignatureValidator must be provided");
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must be provided");
        Reject.ifNull(dcrUtils, "dcrUtils must be provided");
        this.jwkSetService = jwkSetService;
        this.jwtSignatureValidator = jwtSignatureValidator;
        this.trustedDirectoryService = trustedDirectoryService;
        this.dcrUtils = dcrUtils;
    }

    /**
     * validates a Software Statement Assertion's signature. A Software Statement Assertion is a signed JWT issued
     * by a Trusted Directory. It's signature must be validated against a JWK Set hosted by the issuing trusted
     * directory
     * @param transactionId used for logging purposes. This should generally be the transaction id from the IG route's
     *                      context
     * @param ssaSignedJwt the Software Statement Assertion to be validated
     * @return a Promise containing a Response with status 200 (Status.OK) or a DCRSignatureValidationException
     * containing information regarding the reason that the Software Statement Assertion could not be validated
     */
    public Promise<Response, DCRSignatureValidationException> validateSoftwareStatementAssertionSignature(
            @NotNull String transactionId,
            @NotNull SignedJwt ssaSignedJwt) {
        try {

            URL issuingDirectoryJwksUrl = getIssuingDirectoryJwksUrl(transactionId, ssaSignedJwt);
            return this.jwkSetService.getJwkSet(issuingDirectoryJwksUrl).thenAsync(directoryJwkSet -> {
                try {
                    this.jwtSignatureValidator.validateSignature(ssaSignedJwt, directoryJwkSet);
                    log.debug("({}) SSA has a valid signature", transactionId);
                    return Promises.newResultPromise(new Response(Status.OK));
                } catch (SignatureException e) {
                    String errorDescription = "Failed to validate SSA against jwks_uri '" + issuingDirectoryJwksUrl +
                            "'";
                    log.debug("({}) {}", transactionId, errorDescription);
                    return Promises.newExceptionPromise(
                        new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription));
                }
            }, ex -> {
                String errorDescription = "Failed to obtain jwk set from trusted directory uri " +
                        issuingDirectoryJwksUrl;
                log.debug("({}) {}}", transactionId, errorDescription, ex);
                return Promises.newExceptionPromise(
                        new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription));
            });
        } catch (DCRSignatureValidationException dcre) {
            return Promises.newExceptionPromise(dcre);
        }

    }

    /**
     * get the URL at which the JWKS for the SSA can be found
     * @param transactionId log entries will contain the transactionId
     * @param ssa the Software Statement Assertion from which to obtain the JWKS URL
     * @return the URL at which the Software Statement Assertion's signature may be validated
     * @throws DCRSignatureValidationException when the URL can't be obtained from the Software Statement
     */
    private URL getIssuingDirectoryJwksUrl(String transactionId, SignedJwt ssa) throws DCRSignatureValidationException {
        JwtClaimsSet ssaClaimSet = ssa.getClaimsSet();

        final String JWT_NAME = "software statement assertion";
        String ssaIssuer = dcrUtils.getJwtIssuer(JWT_NAME, ssa);
        log.debug("({}) {} issuer is {}", transactionId, JWT_NAME, ssaIssuer);

        TrustedDirectory ssaIssuingDirectory = dcrUtils.getIssuingDirectory(trustedDirectoryService, ssaIssuer);

        String issuingDirectoryJwksUriString = ssaIssuingDirectory.getDirectoryJwksUri();
        return issuingDirectoryJwksUriFromString(transactionId, issuingDirectoryJwksUriString, ssaIssuer);
    }


    /**
     * Create a URL from a string
     * @param transactionId
     * @param urlString
     * @param ssaIssuer
     * @return a URL
     * @throws if the urlString is not a valid URL a {@code DCRSignatureValidationRuntimeException} will be thrown as
     * this indicates a system error as the Trusted Directory has been configured with a badly formed URL string
     */
    private URL issuingDirectoryJwksUriFromString(String transactionId, String urlString, String ssaIssuer) {
        try {
            URL jwksUrl = new URL(urlString);
            return jwksUrl;
        } catch (MalformedURLException e) {
            String errorDescription = "The value of the '" + ssaIssuer + "' Trusted Directory" +
                    " JWKS Uri must be a valid URI";
            log.error("({}) {}", transactionId, errorDescription, e);
            throw new DCRSignatureValidationRuntimeException(errorDescription, e);
        }
    }
}
