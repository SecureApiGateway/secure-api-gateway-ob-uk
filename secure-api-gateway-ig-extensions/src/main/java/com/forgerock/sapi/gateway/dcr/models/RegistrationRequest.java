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

public class RegistrationRequest {

    private static final Logger log = LoggerFactory.getLogger(RegistrationRequest.class);
    private final SignedJwt signedJwt;
    private final ClaimsSetFacade claimsSet;
    private SoftwareStatement softwareStatement;

    public RegistrationRequest(SignedJwt registrationRequestSignedJwt, ClaimsSetFacade registrationRequestClaimsSet) {
        Reject.ifNull(registrationRequestSignedJwt, "registrationRequestSignedJwt must not be null");
        Reject.ifNull(registrationRequestClaimsSet, "registrationRequestClaimsSet must not be null");
        this.signedJwt = registrationRequestSignedJwt;
        this.claimsSet = registrationRequestClaimsSet;
    }

    /**
     * Get the {@code SoftwareStatement} representation of the Software Statement Assertion that was provided in the
     * registration request
     * @return
     */
    public SoftwareStatement getSoftwareStatement() {
        return softwareStatement;
    }

    /**
     * Get the signed jwt representation of the registration request
     * @return a {@code SignedJwt} representation of the registration request
     */
    public SignedJwt getSignedJwt(){
        return signedJwt;
    }

    public ClaimsSetFacade getClaimsSet(){
        return claimsSet;
    }

    /**
     * Set the software statement
     * @param softwareStatement the {@code SoftwareStatement} representation of the software statement provided in the
     *                          registration request
     */
    void setSoftwareStatement(SoftwareStatement softwareStatement) {
        this.softwareStatement = softwareStatement;
    }
}
