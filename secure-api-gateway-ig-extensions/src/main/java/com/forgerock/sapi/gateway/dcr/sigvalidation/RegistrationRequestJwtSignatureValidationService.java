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

import org.forgerock.http.protocol.Response;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;

/**
 * Class that provides validation of registration request JWTs. It handles both those that need to be validated
 * using a JWKS embedded in the Software Statement and those that have a JWKS URI in the software statement
 *
 * For an overview of how this class works see:
 * <a href="https://github.com/SecureApiGateway/SecureApiGateway/wiki/About-Dynamic-Client-Registration">
 *     About Dynamic Client Registration</a>
 */
public class RegistrationRequestJwtSignatureValidationService {
    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestJwtSignatureValidationService.class);
    private final RegistrationRequestJwtSignatureValidatorJwks jwksSignatureValidator;
    private final RegistrationRequestJwtSignatureValidatorJwksUri jwksUriSignatureValidator;


    /**
     * Constructor
     * @param jwksSignatureValidator the service used to validate a jwk against a jwks
     * @param jwksUriSignatureValidator the service used to validate a jwk against a jwks_uri
     */
    public RegistrationRequestJwtSignatureValidationService(
            RegistrationRequestJwtSignatureValidatorJwks jwksSignatureValidator,
            RegistrationRequestJwtSignatureValidatorJwksUri jwksUriSignatureValidator) {
        this.jwksSignatureValidator = jwksSignatureValidator;
        this.jwksUriSignatureValidator = jwksUriSignatureValidator;
    }

    /**
     * Validate a registration request signature
     * @param fapiInteractionId used for log entries so log messages can be traced for a specific API request
     * @param registrationRequest the registration request to be validated
     * @return A Promise containing a Response (OK), or a DCRSignatureValidationException explaining why the
     * registration request signature validation failed
     */
    public Promise<Response, DCRSignatureValidationException> validateJwtSignature(
            String fapiInteractionId, RegistrationRequest registrationRequest) {
        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
        if (softwareStatement.hasJwksUri()) {
            log.debug("({}) SSA contains JwksUri - using the JwksUri Validator", fapiInteractionId);
            return jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(fapiInteractionId,
                    registrationRequest);
        } else {
            log.debug("({}) SSA contains an inline JWKS - using the Jwks Validator", fapiInteractionId);
            return jwksSignatureValidator.validateRegistrationRequestJwtSignature(fapiInteractionId,
                    registrationRequest);
        }
    }
}
