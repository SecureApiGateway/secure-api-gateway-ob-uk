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

import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.jwt.ClaimsSetFacade;
import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.utils.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.jws.JwtReconstructionException;

/**
 * Class to build a {@code RegistrationRequest} from the b64 encoded registration request jwt string
 */
public class RegistrationRequestBuilder {

    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestBuilder.class);
    private final SoftwareStatementBuilder softwareStatementBuilder;
    private final JwtDecoder jwtDecoder;


    /**
     * Construct a {@code RegistrationRequestBuilder)
     * @param softwareStatementBuilder a builder used to construct a {@code SoftwareStatement} from the b64 encoded jwt
     * string found in the 'software_statement' claim of the registration request as specified in
     * <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3.1.1"> rfc7591, section 3.1.1</a>
     * @param jwtDecoder a class used to decode the b64 encoded 'short representation' of the registration request
     * into a SignedJwt representation
     */
    public RegistrationRequestBuilder(SoftwareStatementBuilder softwareStatementBuilder, JwtDecoder jwtDecoder){
        Reject.ifNull(softwareStatementBuilder, "softwareStatementBuilder must not be null");
        Reject.ifNull(jwtDecoder, "jwtDecoder must not be null");
        this.softwareStatementBuilder = softwareStatementBuilder;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * Build a {@code RegistrationRequest} from a the b64 encoded string representation of the regisration request jwt
     * @param txId used for logging context and log tracing
     * @param b64EncodedJwtString the b64 encoded jwt string from the registration request body
     * @return a {@code RegistrationRequest} object
     * @throws DCRRegistrationRequestBuilderException when the {@code RegistrationRequest} can't be build because it is
     * malformed in some way.
     */
    public RegistrationRequest build(String txId, String b64EncodedJwtString)
            throws DCRRegistrationRequestBuilderException {
        try {
            SignedJwt regRequestSignedJwt = jwtDecoder.getSignedJwt(b64EncodedJwtString);
            ClaimsSetFacade regRequestClaimsSet = new ClaimsSetFacade(regRequestSignedJwt.getClaimsSet());
            return createRegistrationRequest(txId, regRequestSignedJwt, regRequestClaimsSet);
        } catch (JwtReconstructionException jre){
            String errorDescription = "Failed to reconstruct registration request jwt from b64Encoded string in request";
            log.debug("({}) ({}", txId, errorDescription);
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_CLIENT_METADATA, errorDescription);
        }

    }

    private RegistrationRequest createRegistrationRequest(String txId, SignedJwt regRequestSignedJwt,
            ClaimsSetFacade regRequestClaimsSet) throws DCRRegistrationRequestBuilderException {
        RegistrationRequest registrationRequest = new RegistrationRequest(regRequestSignedJwt,
                regRequestClaimsSet);
        String SSA_CLAIM_NAME = "software_statement";
        String b64EncodedSsa = null;
        try {
            b64EncodedSsa = regRequestClaimsSet.getStringClaim(SSA_CLAIM_NAME);
        } catch (JwtException e) {
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_CLIENT_METADATA,
                    "Registration Request JWT error: " + e.getMessage());
        }
        SoftwareStatement softwareStatement = softwareStatementBuilder.buildSoftwareStatement(txId, b64EncodedSsa);
        registrationRequest.setSoftwareStatement(softwareStatement);
        return registrationRequest;
    }
}
