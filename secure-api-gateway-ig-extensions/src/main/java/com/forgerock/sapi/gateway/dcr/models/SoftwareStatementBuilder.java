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


import java.net.URL;

import javax.validation.constraints.NotNull;

import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.jwt.ClaimsSetFacade;
import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRSignatureValidationException;
import com.forgerock.sapi.gateway.dcr.utils.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.jws.JwtReconstructionException;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

public class SoftwareStatementBuilder {

    private static final Logger log = LoggerFactory.getLogger(SoftwareStatementBuilder.class);
    private final TrustedDirectoryService trustedDirectoryService;
    private final JwtDecoder jwtDecoder;
    private TrustedDirectory trustedDirectory;

    public SoftwareStatementBuilder(TrustedDirectoryService trustedDirectoryService, JwtDecoder jwtDecoder){
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must not be null");
        Reject.ifNull(jwtDecoder, "jwtDecoder must not be null");
        this.trustedDirectoryService = trustedDirectoryService;
        this.jwtDecoder = jwtDecoder;
    }

    public SoftwareStatement buildSoftwareStatement(String txId, String b64EncodedSoftwareStatement)
            throws DCRRegistrationRequestBuilderException {

        SignedJwt ssaSignedJwt = null;
        try {
            ssaSignedJwt = jwtDecoder.getSignedJwt(b64EncodedSoftwareStatement);
        } catch (JwtReconstructionException e) {
            String errorDescription = "Registration Request's software_statement claim must be a b64 encoded jwt";
            log.debug("({}) {}", txId, errorDescription);
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }
        ClaimsSetFacade ssaClaimsSet = new ClaimsSetFacade(ssaSignedJwt.getClaimsSet());

        this.trustedDirectory = getIssuingDirectory(ssaClaimsSet);
        return createSoftwareStatement(txId, ssaSignedJwt, ssaClaimsSet);
    }

    private SoftwareStatement createSoftwareStatement(String txId, SignedJwt signedJwt, ClaimsSetFacade claimsSet)
            throws DCRRegistrationRequestBuilderException {
        SoftwareStatement softwareStatement = new SoftwareStatement(signedJwt, claimsSet);
        if(trustedDirectory.softwareStatementHoldsJwksUri()){
            softwareStatement.setHasJwksUri(true);
            softwareStatement.setJwksUri(getJwksUri(claimsSet));
        } else {
            softwareStatement.setHasJwksUri(false);
            softwareStatement.setJwksSet(getJwkSet(txId, claimsSet));
        }

        softwareStatement.setOrg_id(getOrgId(claimsSet));
        softwareStatement.setSoftware_id(getSoftwareId(claimsSet));
        return softwareStatement;
    }

    private String getSoftwareId(ClaimsSetFacade claimsSet) throws DCRRegistrationRequestBuilderException {
        String softwareIdClaimName = trustedDirectory.getSoftwareStatementSoftwareIdClaimName();
        try {
            String softwareId = claimsSet.getStringClaim(softwareIdClaimName);
            return softwareId;
        } catch (JwtException e) {
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT,
                    "software statement Jwt error: " + e.getMessage());
        }
    }

    private String getOrgId(ClaimsSetFacade claimsSet) throws DCRRegistrationRequestBuilderException {
        String orgIdClaimName = trustedDirectory.getSoftwareStatementOrgIdClaimName();
        String orgId = null;
        try {
            orgId = claimsSet.getStringClaim(orgIdClaimName);
        } catch (JwtException e) {
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT,
                    "software statement Jwt error: " + e.getMessage());
        }
        return orgId;
    }

    private JWKSet getJwkSet(String transactionId, ClaimsSetFacade claimsSet)
            throws DCRRegistrationRequestBuilderException {
        String jwksClaimName = trustedDirectory.getSoftwareStatementJwksClaimName();
        final JsonValue jwks;
        try {
            jwks = claimsSet.getJsonValueClaim(jwksClaimName);
        } catch (JwtException e) {
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT,
                    "software statement Jwt Error: " + e.getMessage());
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
            String errorDescription = "The software statement claim '" + jwksClaimName + "' does not contain a valid " +
                    "JWKSet";
            log.debug("({}) {}", transactionId, errorDescription);
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }

    }

    private URL getJwksUri(ClaimsSetFacade claimSet) throws DCRRegistrationRequestBuilderException {
        String jwksUriClaimName = trustedDirectory.getSoftwareStatementJwksUriClaimName();
        try {
            return claimSet.getStringClaimAsURL(jwksUriClaimName);
        } catch (JwtException e){
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT,
                    "software statement Jwt Error: " + e.getMessage());
        }
    }


    /**
     * Return the Trusted Directory for the issuer. If no trusted directory exists for that issuer, throw a DCR
     * exception
     * @return a {@code TrustedDirectory}
     * @throws DCRSignatureValidationException if no {@code TrustedDirectory} exists for the ssaIssuer provided
     */
    @NotNull
    private TrustedDirectory getIssuingDirectory(ClaimsSetFacade claimsSet)
            throws DCRRegistrationRequestBuilderException {
        String ssaIssuer = getSsaIssuer(claimsSet);
        TrustedDirectory ssaIssuingDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(ssaIssuer);
        if(ssaIssuingDirectory == null){
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.UNAPPROVED_SOFTWARE_STATEMENT, "The issuer " +
                    "of the software statement is unrecognised");
        }
        return ssaIssuingDirectory;
    }

    /**
     * get the value 'iss' claim, which hold a value indicating the issuer of the JWT.
     * @return a string containing the issuer
     * @throws DCRSignatureValidationException if the JWT does not contain an issuer claim
     */
    @NotNull
    private String getSsaIssuer(ClaimsSetFacade claimsSet) throws DCRRegistrationRequestBuilderException {
        try {
            String ssaIssuer = claimsSet.getIssuer();
            return ssaIssuer;
        } catch (JwtException e) {
            throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT,
                    "software statement Jwt Error: " + e.getMessage());
        }
    }
}
