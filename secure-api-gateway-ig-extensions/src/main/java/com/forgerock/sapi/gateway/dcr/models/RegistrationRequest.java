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
package com.forgerock.sapi.gateway.dcr.models;

import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.common.jwt.SapiJwt;
import com.forgerock.sapi.gateway.common.jwt.SapiJwtBuilder;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;

/**
 * The RegistrationRequest model that holds fields obtained from the b64 url encoded registration request jwt passed
 * to the /register endpoint as a part of a Dynamic Client Registration Request
 */
public class RegistrationRequest extends SapiJwt {

    /**
     * The key of the context attribute in which the dynamic client request object is stored.
     */
    public static final String REGISTRATION_REQUEST_KEY = "registrationRequest";

    private final SoftwareStatement softwareStatement;

    public RegistrationRequest(Builder builder){
        super(builder);
        this.softwareStatement = builder.softwareStatement;
    }

    /**
     * @return the {@code SoftwareStatement} representation of the Software Statement Assertion that was provided in the
     *         registration request
     */
    public SoftwareStatement getSoftwareStatement() {
        return softwareStatement;
    }

    /**
     * Class to build a {@code RegistrationRequest} from the b64 url encoded registration request jwt string.
     */
    public static class Builder extends SapiJwtBuilder {

        private static final Logger log = LoggerFactory.getLogger(Builder.class);
        private final SoftwareStatement.Builder softwareStatementBuilder;
        private SoftwareStatement softwareStatement;

        /**
         * Construct a {@code Builder)
         * @param softwareStatementBuilder a builder used to construct a {@code SoftwareStatement} from the b64 encoded
         * jwt string found in the 'software_statement' claim of the registration request as specified in
         * <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3.1.1"> rfc7591, section 3.1.1</a>
         * @param jwtDecoder a class used to decode the b64 encoded 'short representation' of the registration request
         * into a SignedJwt representation
         */
        public Builder(SoftwareStatement.Builder softwareStatementBuilder, JwtDecoder jwtDecoder){
            super(jwtDecoder);
            Reject.ifNull(softwareStatementBuilder, "softwareStatementBuilder must not be null");
            this.softwareStatementBuilder = softwareStatementBuilder;
        }

        /**
         * Build a {@code RegistrationRequest} from a the b64 encoded string representation of the registration request
         * jwt
         * @param transactionId used for logging context and log tracing
         * @param b64EncodedJwtString the b64 encoded jwt string from the registration request body
         * @return a {@code RegistrationRequest} object
         * @throws DCRRegistrationRequestBuilderException when the {@code RegistrationRequest} can't be build because
         * the b64EncodedJwtString is malformed in some way or doesn't contain the expected claims
         */
        public RegistrationRequest build(String transactionId, String b64EncodedJwtString)
                throws DCRRegistrationRequestBuilderException {
            try {
                super.buildBaseJwt(b64EncodedJwtString);
                populateRegistrationRequest(transactionId);
                return new RegistrationRequest(this);
            } catch (JwtException e) {
                String errorDescription = "Registration Request Jwt error: " + e.getMessage();
                log.debug("({}) {}", transactionId, errorDescription);
                throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_CLIENT_METADATA, errorDescription);
            }
        }

        private void populateRegistrationRequest(String txId)
                throws JwtException, DCRRegistrationRequestBuilderException {
            String SSA_CLAIM_NAME = "software_statement";
            String b64EncodedSsa = this.claimsSet.getStringClaim(SSA_CLAIM_NAME);
            softwareStatement = softwareStatementBuilder.build(txId, b64EncodedSsa);
        }
    }
}