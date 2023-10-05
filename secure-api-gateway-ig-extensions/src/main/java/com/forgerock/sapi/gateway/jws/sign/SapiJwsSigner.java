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
package com.forgerock.sapi.gateway.jws.sign;

import java.util.Map;

import org.forgerock.util.promise.Promise;

/**
 * Interface to implement custom signers
 */
public interface SapiJwsSigner {

    /**
     * Sign a Map<String, Object>, that represents a json structure, supporting critical header claims.<br/>
     * @param payload              {@link Map}
     * @param criticalHeaderClaims {@link Map}
     * @return a promise of the resulting object.<br/>
     * <ul>Promise:
     *     <li>String: The signed JWT (JSON Web Signature (JWS)) of the task's result</li>
     *     <li>SapiJwsSignerException: The exception thrown by the task if it fails</li>
     * </ul>
     */
    Promise<String, SapiJwsSignerException> sign(Map<String, Object> payload, Map<String, Object> criticalHeaderClaims);
}
