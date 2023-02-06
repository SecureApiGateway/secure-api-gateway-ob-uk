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

import java.security.SignatureException;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;

/**
 * Class used to validate a registration request jwt signature against a JWKS embedded in the Software Statement
 */
public class RegistrationRequestJwtSignatureValidatorJwks implements RegistrationRequestJwtSignatureValidator {

    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestJwtSignatureValidatorJwks.class);
    private final JwtSignatureValidator jwtSignatureValidator;

    /**
     * Constructor
     * @param jwtSignatureValidator service that is used to validate a SignedJwt against a JWKSet
     */
    public RegistrationRequestJwtSignatureValidatorJwks(JwtSignatureValidator jwtSignatureValidator) {
        this.jwtSignatureValidator = jwtSignatureValidator;
    }

    @Override
    public Promise<Response, DCRSignatureValidationException> validateRegistrationRequestJwtSignature(
            String transactionId, RegistrationRequest registrationRequest) {
        try {
            SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
            JWKSet jwkSet = softwareStatement.getJwksSet();
            this.jwtSignatureValidator.validateSignature(registrationRequest.getSignedJwt(), jwkSet);
        } catch (SignatureException e) {
            String errorDescription = "Registration request jwt could not be validated against JWKS found in the " +
                    "software statement";
            log.info("({}) {}: {}", transactionId, errorDescription, e.getMessage());
            DCRSignatureValidationException exception = new DCRSignatureValidationException(
                    DCRErrorCode.INVALID_CLIENT_METADATA, errorDescription);
            return Promises.newExceptionPromise(exception);
        } catch (RuntimeException rte){
            log.info("({}) Runtime exception occurred while validating Registration Request (ssa holds JWKS): {}",
                    transactionId, rte.getMessage(), rte);
            return Promises.newRuntimeExceptionPromise(rte);
        }

        log.debug("({}) Registration Request JWT has a valid signature", transactionId);
        return Promises.newResultPromise(new Response(Status.OK));
    }
}
