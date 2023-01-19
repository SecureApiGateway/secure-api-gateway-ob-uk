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

import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.utils.DCRUtils;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

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
    private final TrustedDirectoryService trustedDirectoryService;
    private final DCRUtils dcrUtils;
    private final RegistrationRequestJwtSignatureValidatorJwks jwksSignatureValidator;
    private final RegistrationRequestJwtSignatureValidatorJwksUri jwksUriSignatureValidator;


    /**
     * Constructor
     * @param trustedDirectoryService used to obtain the correct {@code TrustedDirectory} for the Software Statement
     *                               Issuer
     * @param dcrUtils a utility class
     * @param jwksSignatureValidator the service used to validate a jwk against a jwks
     * @param jwksUriSignatureValidator the service used to validate a jwk against a jwks_uri
     */
    public RegistrationRequestJwtSignatureValidationService(
            TrustedDirectoryService trustedDirectoryService, DCRUtils dcrUtils,
            RegistrationRequestJwtSignatureValidatorJwks jwksSignatureValidator,
            RegistrationRequestJwtSignatureValidatorJwksUri jwksUriSignatureValidator) {
        this.trustedDirectoryService = trustedDirectoryService;
        this.dcrUtils = dcrUtils;
        this.jwksSignatureValidator = jwksSignatureValidator;
        this.jwksUriSignatureValidator = jwksUriSignatureValidator;
    }

    /**
     * Validate a registration request signature
     * @param fapiInteractionId used for log entries so log messages can be traced for a specific API request
     * @param ssaClaimsSet the claim set of the ssa from the registration request
     * @param registrationRequestJwt the registration request jwt
     * @return A Promise containing a Response (OK), or a DCRSignatureValidationException explaining why the
     * registration request signature validation failed
     */
    public Promise<Response, DCRSignatureValidationException> validateRegistrationRequestJwtSignature(
            String fapiInteractionId, JwtClaimsSet ssaClaimsSet, SignedJwt registrationRequestJwt) {
        try {
            String ssaIssuer = dcrUtils.getJwtIssuer("software statement assertion", ssaClaimsSet);
            TrustedDirectory ssaIssuingDirectory = dcrUtils.getIssuingDirectory(trustedDirectoryService, ssaIssuer);
            if (ssaIssuingDirectory.softwareStatementHoldsJwksUri()) {
                log.debug("({}) SSA contains JwksUri - using the JwksUri Validator", fapiInteractionId);
                return jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(fapiInteractionId,
                        ssaIssuingDirectory, ssaClaimsSet, registrationRequestJwt);
            } else {
                log.debug("({}) SSA contains an inline JWKS - using the Jwks Validator", fapiInteractionId);
                return jwksSignatureValidator.validateRegistrationRequestJwtSignature(fapiInteractionId,
                        ssaIssuingDirectory,ssaClaimsSet, registrationRequestJwt);
            }
        } catch (DCRSignatureValidationException dsve) {
            return Promises.newExceptionPromise(dsve);
        }
    }
}
