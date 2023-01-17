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
package com.forgerock.sapi.gateway.dcr.request;

import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.promise.Promise;

import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;

public interface DCRRegistrationRequestValidator {

    /**
     * Validate the registration request signature
     * @param transactionId used for logging
     * @param ssaIssuingDirectory the {@code TrustedDirectory} for the issuer of the software statement provided in the
     *                            registration request
     * @param ssaClaimsSet the JWT claims of software statement supplied in the registration request
     * @param registrationRequestJwt the registration request jwt that is to be validated
     * @return a promise that provides either a response with Status of OK, or a DCRSignatureValidationException
     * containing details of why the validation of the registration request failed
     */
    Promise<Response, DCRSignatureValidationException> validateRegistrationRequestJwtSignature(String transactionId,
            TrustedDirectory ssaIssuingDirectory, JwtClaimsSet ssaClaimsSet,SignedJwt registrationRequestJwt);
}
