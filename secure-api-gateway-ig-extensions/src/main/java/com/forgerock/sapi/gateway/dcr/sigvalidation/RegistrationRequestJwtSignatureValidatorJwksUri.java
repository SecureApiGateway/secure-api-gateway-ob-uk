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

import java.net.URL;
import java.security.SignatureException;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;

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
            String transactionId, RegistrationRequest registrationRequest) {
        try {
            SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
            URL softwareStatementsJwksUri = softwareStatement.getJwksUri();
            return jwkSetService.getJwkSet(softwareStatementsJwksUri).thenAsync(jwkSet -> {
                log.debug("({}) JWKSet to validate against is {}", transactionId, jwkSet);
                try {
                    this.jwtSignatureValidator.validateSignature(registrationRequest.getSignedJwt(), jwkSet);
                    log.info("({}) Registration Request signature is valid", transactionId);
                    return Promises.newResultPromise(new Response(Status.OK));
                } catch (SignatureException e) {
                    String errorDescription = "Failed to validate registration request signature against jwkSet" +
                            " '" + jwkSet + "'";
                    log.debug("({}) {}", transactionId, errorDescription);
                    return Promises.newExceptionPromise(
                            new DCRSignatureValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, errorDescription));
                }
            }, ex -> {
                String errorDescription = "Failed to obtain jwks from software statement's jwks_uri: '" +
                        softwareStatementsJwksUri + "'";
                log.debug("({}) {}", transactionId, errorDescription);
                throw new DCRSignatureValidationException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
            });
        } catch (RuntimeException rte){
            log.info("({}) Runtime exception occurred while validating Registration Request (ssa holds JWKS_URI): {}",
                    transactionId, rte.getMessage(), rte);
            return Promises.newRuntimeExceptionPromise(rte);
        }
    }
}
