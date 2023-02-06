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

import org.apache.ivy.util.StringUtils;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.Reject;

import com.forgerock.sapi.gateway.common.jwt.ClaimsSetFacade;
import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;

/**
 * Parent of JwtBuilder classes. Holds a jwt decoder and provides common methods
 */
public abstract class SapiJwtBuilder {

    protected final JwtDecoder jwtDecoder;
    protected String b64EncodedJwtString;
    protected SignedJwt signedJwt;
    protected String kid;
    protected ClaimsSetFacade claimsSet;
    protected String issuer;

    public SapiJwtBuilder(JwtDecoder jwtDecoder) {
        Reject.ifNull(jwtDecoder, "jwtDecoder must not be null");
        this.jwtDecoder = jwtDecoder;
    }

    protected void buildBaseJwt(String b64EncodedJwtString) throws JwtException {
        Reject.ifNull(b64EncodedJwtString, "b64EncodedJwtString must not be null");
        this.b64EncodedJwtString = b64EncodedJwtString;
        this.signedJwt = getSignedJwt();
        this.kid = getKeyIdFromSignedJwt(this.signedJwt);
        this.claimsSet = new ClaimsSetFacade(signedJwt.getClaimsSet());
        this.issuer = claimsSet.getIssuer();
    }

    /**
     * Create a {@code SignedJwt} representation from the b64 url encoded jws string
     * @return a {@code SignedJwt} representation of the b64 url encoded jwt string.
     * @throws JwtException when the b64 url encoded string can't be decoded into a SignedJwt representation
     */
    private SignedJwt getSignedJwt() throws JwtException {
        return jwtDecoder.getSignedJwt(b64EncodedJwtString);
    }

    /**
     * Get the keyId from the header
     * @param signedJwt the signed jwt to obtain the keyId from
     * @return the keyId
     * @throws JwtException throws if the jwt has no header, or has no valid keyId
     */
    private String getKeyIdFromSignedJwt(SignedJwt signedJwt) throws JwtException {
        JwsHeader header = signedJwt.getHeader();
        if(header == null){
            throw new JwtException("Jwt must have a header");
        }
        String kid =  header.getKeyId();
        if(StringUtils.isNullOrEmpty(kid)){
            throw new JwtException("Jwt header must contain a 'kid' claim");
        }
        return kid;
    }


}
