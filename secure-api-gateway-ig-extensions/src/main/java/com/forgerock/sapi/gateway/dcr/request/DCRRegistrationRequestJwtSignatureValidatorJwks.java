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

import java.security.SignatureException;

import org.apache.ivy.util.StringUtils;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.request.DCRSignatureValidationException.ErrorCode;

import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;

/**
 * Class used to validate a registration request jwt signature against a JWKS embedded in the Software Statement
 */
public class DCRRegistrationRequestJwtSignatureValidatorJwks implements DCRRegistrationRequestValidator {

    private static final Logger log = LoggerFactory.getLogger(DCRRegistrationRequestJwtSignatureValidatorJwks.class);
    private final JwtSignatureValidator jwtSignatureValidator;

    /**
     * Constructor
     * @param jwtSignatureValidator service that is used to validate a SignedJwt against a JWKSet
     */
    public DCRRegistrationRequestJwtSignatureValidatorJwks(JwtSignatureValidator jwtSignatureValidator) {
        this.jwtSignatureValidator = jwtSignatureValidator;
    }

    @Override
    public Promise<Response, DCRSignatureValidationException> validateRegistrationRequestJwtSignature(
            String transactionId, TrustedDirectory ssaIssuingDirectory, JwtClaimsSet ssaClaimsSet,
            SignedJwt registrationRequestJwt) {
        try {
            String jwksClaimName = getSoftwareStatementJwksClaimName(transactionId, ssaIssuingDirectory);
            JWKSet jwkSet = getJwkSet(transactionId, jwksClaimName, ssaClaimsSet);
            this.jwtSignatureValidator.validateSignature(registrationRequestJwt, jwkSet);
        } catch (SignatureException e) {
            String errorDescription = "Registration request jwt could not be validated against JWKS found in the " +
                    "software statement";
            log.info("({}) {}: {}", transactionId, errorDescription, e.getMessage());
            DCRSignatureValidationException exception = new DCRSignatureValidationException(
                    ErrorCode.INVALID_CLIENT_METADATA, errorDescription);
            return Promises.newExceptionPromise(exception);
        } catch (DCRSignatureValidationException e) {
            return Promises.newExceptionPromise(e);
        }

        log.debug("({}) Registration Request JWT has a valid signature", transactionId);
        return Promises.newResultPromise(new Response(Status.OK));
    }

    private String getSoftwareStatementJwksClaimName(String transactionId, TrustedDirectory ssaIssuingDirectory){
        String jwksClaimName = ssaIssuingDirectory.getSoftwareStatementJwksClaimName();
        if (StringUtils.isNullOrEmpty(jwksClaimName)) {
            String errorDescription = "Software statement must contain a claim holding the JWKS against which keys" +
                    "associated with the software statement must be validated";
            log.debug("({}) {}", transactionId, errorDescription);
            throw new DCRSignatureValidationRuntimeException(errorDescription);
        }
        return jwksClaimName;
    }

    private JWKSet getJwkSet(String transactionId, String claimName, JwtClaimsSet ssaClaimsSet)
            throws DCRSignatureValidationException {
        final JsonValue jwks = ssaClaimsSet.get(claimName);
        if(jwks.getObject() == null){
            String errorDescription = "The software_statement must contain the claim '" + claimName + "'";
            log.debug("({}) {}", transactionId, errorDescription);
            throw new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }
        log.debug("({}) jwks from software statement is {}", transactionId, jwks);
        try {
            // Note, if the jwks can't be parsed (does not have a "keys" entry) it will return a non-null empty JWKSet
            JWKSet result =  JWKSet.parse(jwks);
            if(result.getJWKsAsJsonValue().size() == 0){
                throw new JsonException("JsonValues does not contain valid JWKS data");
            }
            return result;
        } catch (JsonException je){
            String errorDescription = "The software statement claim " + claimName + "' does not contain a valid JWKSet";
            log.debug("({}) {}", transactionId, errorDescription);
            throw new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }
    }

}
