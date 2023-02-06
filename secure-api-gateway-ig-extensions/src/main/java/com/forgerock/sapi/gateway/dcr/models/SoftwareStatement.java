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

import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.common.jwt.SapiJwt;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.utils.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

public class SoftwareStatement extends SapiJwt {

    public static class Builder extends SapiJwtBuilder{
        private static final Logger log = LoggerFactory.getLogger(Builder.class);
        private final TrustedDirectoryService trustedDirectoryService;

        private TrustedDirectory trustedDirectory;
        private String orgId;
        private String softwareId;
        private boolean hasJwksUri;
        private URL jwksUri;
        private JWKSet jwkSet;
        private URL trustedDirectoryJwksUrl;

        public Builder(TrustedDirectoryService trustedDirectoryService, JwtDecoder jwtDecoder) {
            super(jwtDecoder);
            Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must not be null");
            this.trustedDirectoryService = trustedDirectoryService;
        }

        public SoftwareStatement build(String transactionId, String b64EncodedSoftwareStatement) throws DCRRegistrationRequestBuilderException {
            try {
                buildBaseJwt(b64EncodedSoftwareStatement);
                this.trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(issuer);
                if(this.trustedDirectory == null){
                    throw new DCRRegistrationRequestBuilderException(DCRErrorCode.UNAPPROVED_SOFTWARE_STATEMENT,
                            "The issuer of the software statement is unrecognised");
                }
                getSsaSpecificFieldsFromJwt(transactionId, trustedDirectory);
            } catch (JwtException je){
                throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT,
                        "Software Statement JWT error: " + je.getMessage());
            }
            return new SoftwareStatement(this);
        }

        private void getSsaSpecificFieldsFromJwt(String transactionId, TrustedDirectory trustedDirectory) throws JwtException {
            if(trustedDirectory.softwareStatementHoldsJwksUri()){
                this.hasJwksUri = true;
                this.jwksUri = claimsSet.getStringClaimAsURL(trustedDirectory.getSoftwareStatementJwksUriClaimName());
            } else {
                this.hasJwksUri = false;
                this.jwkSet = getJwkSet(transactionId);
            }
            this.orgId = claimsSet.getStringClaim(trustedDirectory.getSoftwareStatementOrgIdClaimName());
            this.softwareId = claimsSet.getStringClaim(trustedDirectory.getSoftwareStatementSoftwareIdClaimName());
            this.trustedDirectoryJwksUrl = trustedDirectory.getDirectoryJwksUri();

        }

        private JWKSet getJwkSet(String transactionId)
                throws  JwtException {
            String jwksClaimName = this.trustedDirectory.getSoftwareStatementJwksClaimName();
            final JsonValue jwks = claimsSet.getJsonValueClaim(jwksClaimName);
            log.debug("({}) jwks from software statement is {}", transactionId, jwks);
                // Note, if the jwks can't be parsed (does not have a "keys" entry) it will return a non-null empty JWKSet
            JWKSet result =  JWKSet.parse(jwks);
            if(result.getJWKsAsJsonValue().size() == 0){
                throw new JsonException("JsonValues does not contain valid JWKS data");
            }
            return result;
        }
    }

    private String orgId;
    private String softwareId;
    private boolean hasJwksUri;
    private URL jwksUri;
    private JWKSet jwksSet;

    // The jwks_uri of the trusted directory against which the Software Statement signature may be validated
    private final URL trustedDirectoryJwksUrl;

    public SoftwareStatement(Builder builder){
        super(builder.issuer, builder.kid, builder.b64EncodedJwtString, builder.signedJwt, builder.claimsSet);
        this.orgId = builder.orgId;
        this.softwareId = builder.softwareId;
        this.hasJwksUri = builder.hasJwksUri;
        this.jwksUri = builder.jwksUri;
        this.jwksSet = builder.jwkSet;
        this.trustedDirectoryJwksUrl = builder.trustedDirectoryJwksUrl;
    }

    /**
     * Get the URL against which the software statement assertions signature may be validated
     * @return the URL
     */
    public URL getTrustedDirectoryJwksUrl() {
        return trustedDirectoryJwksUrl;
    }

    /**
     * @param hasJwksUri
     */
    void setHasJwksUri(boolean hasJwksUri) {
        this.hasJwksUri = hasJwksUri;
    }

    public boolean hasJwksUri() {
        return hasJwksUri;
    }

    public String getOrgId() {
        return orgId;
    }

    void setOrgId(String orgId) {
        this.orgId = orgId;
    }

    public String getSoftwareId() {
        return softwareId;
    }

    public void setSoftwareId(String softwareId) {
        this.softwareId = softwareId;
    }

    public URL getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(URL jwksUri) {
        this.jwksUri = jwksUri;
    }

    public JWKSet getJwksSet() {
        return jwksSet;
    }

    public void setJwksSet(JWKSet jwksSet) {
        this.jwksSet = jwksSet;
    }
}
