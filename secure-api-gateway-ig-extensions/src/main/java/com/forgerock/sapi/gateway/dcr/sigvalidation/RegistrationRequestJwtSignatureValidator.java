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
package com.forgerock.sapi.gateway.dcr.sigvalidation;

import org.forgerock.http.protocol.Response;
import org.forgerock.util.promise.Promise;

import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;

public interface RegistrationRequestJwtSignatureValidator {

    /**
     * Validate the registration request signature
     * @param transactionId used for logging
     * @param registrationRequest the registration request jwt that is to be validated
     * @return a promise that provides either a response with Status of OK, or a DCRSignatureValidationException
     * containing details of why the validation of the registration request failed
     */
    Promise<Response, DCRSignatureValidationException> validateRegistrationRequestJwtSignature(String transactionId,
            RegistrationRequest registrationRequest);
}
