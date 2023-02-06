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

import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.Reject;

public class SapiJwt {

    private final String b64EncodedJwtString;
    private final SignedJwt signedJwt;
    private final ClaimsSetFacade claimsSet;
    private final String keyId;
    private final String issuer;

    public SapiJwt(String issuer, String kid, String b64EncodedJwtString, SignedJwt signedJwt, ClaimsSetFacade claimsSet) {
        Reject.ifNull(issuer, "issuer must not be null");
        Reject.ifNull(kid, "kid must not be null");
        Reject.ifNull(b64EncodedJwtString, "b64EncodedJwtString must not be null");
        Reject.ifNull(signedJwt, "signedJwt must not be null");
        Reject.ifNull(claimsSet, "claimsSet must not be null");
        this.b64EncodedJwtString = b64EncodedJwtString;
        this.signedJwt = signedJwt;
        this.claimsSet = claimsSet;
        this.keyId = kid;
        this.issuer = issuer;
    }


    public String getB64EncodedJwtString() {
        return b64EncodedJwtString;
    }

    /**
     * Get the signed jwt representation of the registration request
     *
     * @return a {@code SignedJwt} representation of the registration request
     */
    public SignedJwt getSignedJwt() {
        return signedJwt;
    }


    public ClaimsSetFacade getClaimsSet() {
        return claimsSet;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getIssuer() {
        return issuer;
    }



    /**
     * Produce a string representation of the Jwt that includes the kid and an abbreviated b64 encoded jwt string
     *
     * @return a string representation
     */
    @Override
    public String toString() {
        String builder = "kid: '" + keyId + "'" + ", jwtString: '" +
                b64EncodedJwtString.substring(0, 6) +
                "..." +
                b64EncodedJwtString.substring((b64EncodedJwtString.length() - 7));
        return builder;
    }

    /**
     * Produce a detailed output of the Registration Request Jwt that includes the whole b64 encoded jwt string
     *
     * @return
     */
    public String toDetailedString() {
        return "kid: '" + keyId + "'" + ", jwtString: '" + b64EncodedJwtString;
    }
}
