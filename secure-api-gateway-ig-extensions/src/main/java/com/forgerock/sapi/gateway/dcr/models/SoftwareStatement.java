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

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.Reject;

import com.forgerock.sapi.gateway.common.jwt.ClaimsSetFacade;
import com.forgerock.sapi.gateway.common.jwt.JwtException;

public class SoftwareStatement {

    private final SignedJwt signedJwt;
    private final ClaimsSetFacade claimsSet;
    private String org_id;
    private String software_id;
    private boolean hasJwksUri;
    private URL jwksUri;
    private JWKSet jwksSet;
    public SoftwareStatement(SignedJwt ssaSignedJwt, ClaimsSetFacade ssaClaimsSet) {
        Reject.ifNull(ssaSignedJwt, "ssaSignedJwt must not be null");
        Reject.ifNull(ssaClaimsSet, "ssaClaimsSet must not be null");
        this.signedJwt = ssaSignedJwt;
        this.claimsSet = ssaClaimsSet;
    }

    public SignedJwt getSignedJwt() {
        return signedJwt;
    }

    public ClaimsSetFacade getClaimsSet() {
        return claimsSet;
    }

    public void setHasJwksUri(boolean hasJwksUri) {
        this.hasJwksUri = hasJwksUri;
    }
    public boolean hasJwksUri() {
        return hasJwksUri;
    }

    public String getOrg_id() {
        return org_id;
    }

    public void setOrg_id(String org_id) {
        this.org_id = org_id;
    }

    public String getSoftware_id() {
        return software_id;
    }

    public void setSoftware_id(String software_id) {
        this.software_id = software_id;
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

    public String getStringClaim(String claimName) throws JwtException {
        return this.claimsSet.getStringClaim(claimName);
    }
}
