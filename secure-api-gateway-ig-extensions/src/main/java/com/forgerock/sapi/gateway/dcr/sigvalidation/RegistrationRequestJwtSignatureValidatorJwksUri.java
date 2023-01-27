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
package com.forgerock.sapi.gateway.dcr.sigvalidation;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.SignatureException;

import org.apache.ivy.util.StringUtils;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;

import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRSignatureValidationException.ErrorCode;

/**
 * Class used to validate a registration request jwt signature against a JWKS URI embedded in the Software Statement
 */
public class RegistrationRequestJwtSignatureValidatorJwksUri implements RegistrationRequestJwtSignatureValidator {

    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestJwtSignatureValidatorJwksUri.class);
    private final JwkSetService jwkSetService;
    private final JwtSignatureValidator jwtSignatureValidator;

    /**
     * Constructor
     * @param jwkSetService a service that gets the JWKS from a JWKS URI
     * @param jwtSignatureValidator service that is used to validate a SignedJwt against a JWKSet
     */
    public RegistrationRequestJwtSignatureValidatorJwksUri(JwkSetService jwkSetService,
            JwtSignatureValidator jwtSignatureValidator) {
        this.jwkSetService = jwkSetService;
        this.jwtSignatureValidator = jwtSignatureValidator;
    }

    @Override
    public Promise<Response, DCRSignatureValidationException> validateRegistrationRequestJwtSignature(
            String transactionId, TrustedDirectory ssaIssuingDirectory, JwtClaimsSet ssaClaimsSet,
            SignedJwt registrationRequestJwt) {
        try {
            URL softwareStatementsJwksUri = getSoftwareStatementJwksUri(transactionId, ssaIssuingDirectory,
                    ssaClaimsSet);
            return jwkSetService.getJwkSet(softwareStatementsJwksUri).thenAsync(jwkSet -> {
                log.debug("({}) JWKSet to validate against is {}", transactionId, jwkSet);
                try {
                    this.jwtSignatureValidator.validateSignature(registrationRequestJwt, jwkSet);
                    log.info("({}) Registration Request signature is valid", transactionId);
                    return Promises.newResultPromise(new Response(Status.OK));
                } catch (SignatureException e) {
                    String errorDescription = "Failed to validate registration request signature against jwkSet" +
                            " '" + jwkSet + "'";
                    log.debug("({}) {}", transactionId, errorDescription);
                    return Promises.newExceptionPromise(
                            new DCRSignatureValidationException(ErrorCode.INVALID_CLIENT_METADATA, errorDescription));
                }
            }, ex -> {
                String errorDescription = "Failed to obtain jwks from software statement's jwks_uri: '" +
                        softwareStatementsJwksUri + "'";
                log.debug("({}) {}", transactionId, errorDescription);
                throw new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
            });
        } catch (DCRSignatureValidationException e) {
            return Promises.newExceptionPromise(e);
        } catch (RuntimeException rte){
            log.info("({}) Runtime exception occurred while validating Registration Request (ssa holds JWKS_URI): {}",
                    transactionId, rte.getMessage(), rte);
            return Promises.newRuntimeExceptionPromise(rte);
        }
    }

    private URL getSoftwareStatementJwksUri(String transactionId, TrustedDirectory ssaIssuingDirectory,
            JwtClaimsSet ssaClaimsSet) throws DCRSignatureValidationException {

        String jwksUriClaimName = getSoftwareStatementJwksUriClaimName(transactionId, ssaIssuingDirectory);
        String jwksUri = getSoftwareStatementJwksUriValue(transactionId, jwksUriClaimName, ssaClaimsSet);
        try {
            URL softwareStatementsJwksUri = new URL(jwksUri);
            if (!"https".equals(softwareStatementsJwksUri.getProtocol())) {
                String errorDescription = "registration request's software_statement jwt '" + jwksUriClaimName +
                        "' must contain an HTTPS URI";
                log.debug("({}) {}", transactionId, errorDescription);
                throw new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
            }
            return softwareStatementsJwksUri;
        } catch (MalformedURLException e) {
            String errorDescription = "The registration request jwt signature could not be validated. The '" +
                    jwksUriClaimName + "' claim in the software statement has a value of '" + jwksUri + "' this " +
                    "value must be a valid URL";
            log.debug("({}) {}", transactionId, errorDescription);
            throw new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }
    }

    private String getSoftwareStatementJwksUriClaimName(String transactionId, TrustedDirectory ssaIssuingDirectory){
        String jwksUriClaimName = ssaIssuingDirectory.getSoftwareStatementJwksUriClaimName();
        if (StringUtils.isNullOrEmpty(jwksUriClaimName)) {
            String errorDescription = "Trusted Directory for " + ssaIssuingDirectory.getIssuer() + " has no " +
                    "softwareStatementJwksUriClaimName value";
            log.error("({}) {}: TrustedDirectory.getSoftwareStatementJwksUriClaimName() returned null!",
                    transactionId, errorDescription);
            throw new DCRSignatureValidationRuntimeException(errorDescription);
        }
        return jwksUriClaimName;
    }

    private String getSoftwareStatementJwksUriValue(String transactionId, String claimName, JwtClaimsSet jwtClaimsSet)
            throws DCRSignatureValidationException {
        String jwksUri = jwtClaimsSet.getClaim(claimName, String.class);
        if (StringUtils.isNullOrEmpty(jwksUri)) {
            String errorDescription = "Software statement must contain a claim for the JWKS URI against which " +
                    "keys associated with the software statement must be validated";
            log.debug("({}) {}", transactionId, errorDescription);
            throw new DCRSignatureValidationException(DCRSignatureValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT,
                    errorDescription);
        }
        return jwksUri;
    }

}
