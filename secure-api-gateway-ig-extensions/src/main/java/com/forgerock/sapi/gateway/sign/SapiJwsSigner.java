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
package com.forgerock.sapi.gateway.sign;

import java.util.Map;

/**
 * Signer Interface util to define concrete signer implementations
 */
public interface SapiJwsSigner<T> {

    String CRIT_CLAIM = "crit";
    /**
     * Sign method signature
     * @param payload {@link Map}
     * @return Signed JWT as {@link String}
     * @throws Exception
     */
    String sign(Map<String, Object> payload) throws Exception;

    /**
     * Add critical header claims <br/>
     * ex. Signer.critClaims(critClaimsMap).sign(payloadMap) <br/>
     * @param criticalHeaderClaims
     * @return T
     */
    T critClaims(Map<String, Object> criticalHeaderClaims);
}
