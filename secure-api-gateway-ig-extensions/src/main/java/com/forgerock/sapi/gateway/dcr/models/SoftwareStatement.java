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
import com.forgerock.sapi.gateway.common.jwt.SapiJwtBuilder;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

/**
 * The SoftwareStatement model that holds fields obtained from the b64 url encoded software statement assertion jwt
 * passed to the /register endpoint as a part of a Dynamic Client Registration Request Jwt
 */
public class SoftwareStatement extends SapiJwt {

    // The jwks_uri of the trusted directory against which the Software Statement signature may be validated
    private final URL trustedDirectoryJwksUrl;
    private final String orgId;
    private final String softwareId;
    private final boolean hasJwksUri;
    private final URL jwksUri;
    private final JWKSet jwksSet;


    /**
     * Constructor takes a builder
     *
     * @param builder a {@code SoftwareStatement.Builder}
     */
    public SoftwareStatement(Builder builder) {
        super(builder);
        this.orgId = builder.orgId;
        this.softwareId = builder.softwareId;
        this.hasJwksUri = builder.hasJwksUri;
        this.jwksUri = builder.jwksUri;
        this.jwksSet = builder.jwkSet;
        this.trustedDirectoryJwksUrl = builder.trustedDirectoryJwksUrl;
    }

    /**
     * @return the URL against which the software statement assertions signature may be validated
     */
    public URL getTrustedDirectoryJwksUrl() {
        return trustedDirectoryJwksUrl;
    }

    /**
     * @return true if the software statement has a jwks uri from which the JWKS can be fetched, or false if the
     * software statement has an embedded JWKS.
     */
    public boolean hasJwksUri() {
        return hasJwksUri;
    }

    /**
     * @return the unique ID of the Organisation in the Trusted Directory that issued the software statement
     */
    public String getOrgId() {
        return orgId;
    }

    /**
     * @return the unique ID of the Software Statement in the Trusted Directory that issued the software statement
     */
    public String getSoftwareId() {
        return softwareId;
    }

    /**
     * @return if hasJwksUri returns true, then this will return a URL that defines the URL at which the JWKS that holds
     * all of the public keys associated with the software statement. The JWKS obtained from this URL can be used to
     * validate all the transport, signing keys and encryption keys that will be used by the ApiClient
     */
    public URL getJwksUri() {
        return jwksUri;
    }

    /**
     * @return if hasJwksUri returns fals, then this will return a JWKS that will contain all of the public keys that
     * are associated with the software statement. This JWKS can be used to validate all the transport, signing keys
     * and encryption keys that will be used by the ApiClient
     */
    public JWKSet getJwksSet() {
        return jwksSet;
    }

    /**
     * A builder that may be used to construct a Software Statement
     */
    public static class Builder extends SapiJwtBuilder {
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

        /**
         * Processes the b64UrlEncoded jwt String and obtains the fields required to create a Software Statement
         * from the jwt and it's claims.
         * @param transactionId used for logging purposes
         * @param b64EncodedSoftwareStatement the b64 Url Encoded String form of the Software Statement, i.e.
         *                                    the Software Statement Assertion
         * @return a SoftwareStatement initialised with data from the JWT
         * @throws DCRRegistrationRequestBuilderException if there are issues processing the b64 Url Encoded Jwt, or
         * if required claims are not present, or not in the expected form
         */
        public SoftwareStatement build(String transactionId, String b64EncodedSoftwareStatement)
                throws DCRRegistrationRequestBuilderException {
            try {
                buildBaseJwt(b64EncodedSoftwareStatement);
                this.trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(issuer);
                if (this.trustedDirectory == null) {
                    throw new DCRRegistrationRequestBuilderException(DCRErrorCode.UNAPPROVED_SOFTWARE_STATEMENT,
                            "The issuer of the software statement is unrecognised");
                }
                getSsaSpecificFieldsFromJwt(transactionId, trustedDirectory);
            } catch (JwtException je) {
                throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT,
                        "Software Statement JWT error: " + je.getMessage());
            }
            return new SoftwareStatement(this);
        }

        private void getSsaSpecificFieldsFromJwt(String transactionId, TrustedDirectory trustedDirectory) throws JwtException {
            if (trustedDirectory.softwareStatementHoldsJwksUri()) {
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
                throws JwtException {
            String jwksClaimName = this.trustedDirectory.getSoftwareStatementJwksClaimName();
            final JsonValue jwks = claimsSet.getJsonValueClaim(jwksClaimName);
            log.debug("({}) jwks from software statement is {}", transactionId, jwks);
            // Note, if the jwks can't be parsed (does not have a "keys" entry) it will return a non-null empty JWKSet
            JWKSet result = JWKSet.parse(jwks);
            if (result.getJWKsAsJsonValue().size() == 0) {
                throw new JsonException("JsonValues does not contain valid JWKS data");
            }
            return result;
        }
    }
}
