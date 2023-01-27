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
package com.forgerock.sapi.gateway.jws;

/**
 * Checked exception that can be thrown when reconstruction of a JWT from a b64 encoded JWT string fails
 */
public class JwtReconstructionException extends Exception {

    public JwtReconstructionException() {
    }

    public JwtReconstructionException(String message) {
        super(message);
    }

    public JwtReconstructionException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtReconstructionException(Throwable cause) {
        super(cause);
    }

    public JwtReconstructionException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
