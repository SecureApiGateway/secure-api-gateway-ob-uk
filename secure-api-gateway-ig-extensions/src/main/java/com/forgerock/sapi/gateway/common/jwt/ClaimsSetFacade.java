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
package com.forgerock.sapi.gateway.common.jwt;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.ivy.util.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.Reject;

/**
 * Wrapper for client provided Jwt. The JwtClaimSet class throws many Runtime Exceptions when claims can't be cast to
 * the expected type, returns null when the claim does not exist, etc. This means there needs to be significant error
 * handling ever time we expect a claim to be in the claim set, but the jwt has been provided by the client and we can't
 * guarantee what is in there.
 *
 * This wrapper class can be used to build accessor methods that catch runtime exceptions and throw checked exceptions.
 * Using this class will force client code to handle those exceptions and ensure that a decent error message will
 * ultimately be provided to the client.
 */
public class ClaimsSetFacade {
    private JwtClaimsSet claimsSet;

    public ClaimsSetFacade(JwtClaimsSet claimsSet){
        Reject.ifNull(claimsSet, "claimSet must not be null");
        this.claimsSet = claimsSet;
    }

    /**
     * Get a String type claim from the JWT
     * @param claimName the name of the claim
     * @return a valid (i.e. not null or empty) {@code String} containing the value associated with the claim
     * @throws JwtException if either the claim does not exist or it's value is either empty or not a String value
     */
    public String getStringClaim(String claimName) throws JwtException {
        checkClaimName(claimName);
        try {
            String claimValue = this.claimsSet.getClaim(claimName, String.class);
            if(StringUtils.isNullOrEmpty(claimValue)){
                throw new JwtException("Jwt claim '" + claimName + "' must be valid string value");
            }
            return claimValue;
        } catch (ClassCastException exception){
            throw new JwtException("Jwt must contain String claim '" + claimName + "'");
        }
    }


    public URL getStringClaimAsURL(String claimName) throws JwtException {
        checkClaimName(claimName);
        try {
            String claimValueAsString = this.claimsSet.getClaim(claimName, String.class);
            if(StringUtils.isNullOrEmpty(claimValueAsString)){
                throw new JwtException("Jwt claim '" + claimName + "' must be valid URL as a String value");
            }
            try {
                URL claimValueAsURL = new URL(claimValueAsString);
                return claimValueAsURL;
            } catch (MalformedURLException e) {
                throw new JwtException("Jwt claim '" + claimName + "' must be a valid URL as a String Value");
            }
        } catch (ClassCastException exception){
            throw new JwtException("Jwt must contain URL claim '" + claimName + "'");
        }
    }

    public JsonValue getJsonValueClaim(String claimName) throws JwtException {
       checkClaimName(claimName);
       JsonValue claimValue = claimsSet.get(claimName);
       if(claimValue == null || claimValue.getObject() == null){
           throw new JwtException("Jwt must have '" + claimName + "' claim");
       }
        return claimValue;
    }

    private void checkClaimName(String claimName){
        if(StringUtils.isNullOrEmpty(claimName)){
            throw new IllegalArgumentException("claimName must not be null or empty");
        }
    }

    public String getIssuer() throws JwtException {
        String issuer = claimsSet.getIssuer();
        if(StringUtils.isNullOrEmpty(issuer)){
            throw new JwtException("Jwt must contain 'iss' claim");
        }
        return issuer;
    }
}
