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
package com.forgerock.sapi.gateway.dcr;

import java.net.URI;

import org.forgerock.json.jose.jws.SignedJwt;

public class ApiClient {

    private String oauth2ClientId;
    private String softwareClientId;
    private String clientName;
    private URI jwksUri;
    private SignedJwt softwareStatementAssertion;
    private ApiClientOrganisation organisation;

    public ApiClient(){
    }

    public String getOauth2ClientId() {
        return oauth2ClientId;
    }

    public void setOauth2ClientId(String oauth2ClientId) {
        this.oauth2ClientId = oauth2ClientId;
    }

    public String getSoftwareClientId() {
        return softwareClientId;
    }

    public void setSoftwareClientId(String softwareClientId) {
        this.softwareClientId = softwareClientId;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public URI getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(URI jwksUri) {
        this.jwksUri = jwksUri;
    }

    public SignedJwt getSoftwareStatementAssertion() {
        return softwareStatementAssertion;
    }

    public void setSoftwareStatementAssertion(SignedJwt softwareStatementAssertion) {
        this.softwareStatementAssertion = softwareStatementAssertion;
    }

    public ApiClientOrganisation getOrganisation() {
        return organisation;
    }

    public void setOrganisation(ApiClientOrganisation organisation) {
        this.organisation = organisation;
    }
}
