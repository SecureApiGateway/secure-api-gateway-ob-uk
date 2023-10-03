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
package com.forgerock.sapi.gateway.jwks.sign;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Default signer result implementation that represents the object returned after compute a signature <br/>
 * <ul>
 *     <li>The caller can get the signedJwt</li>
 *     <li>The caller can check the error event messages produced by the signing process</li>
 * </ul>
 * <lu>
 *     <li>When the process finish successfully the value of signedJwt is used to store the signed JWT, and the error list is empty</li>
 *     <li>When the process fails, produces error event messages, the result object provides a list of these error messages, and the signedJwt is null</li>
 * </lu>
 */
public class DefaultSapiJwsSignerResult implements SapiJwsSignerResult {
    private final String signedJwt;
    private List<String> errors;

    public DefaultSapiJwsSignerResult(String signedJwt) {
        this.signedJwt = signedJwt;
        this.errors = Collections.EMPTY_LIST;
    }

    public DefaultSapiJwsSignerResult(List<String> errors) {
        this.signedJwt = null;
        this.errors = errors;
    }

    @Override
    public String getSignedJwt() {
        return signedJwt;
    }

    @Override
    public boolean hasErrors() {
        return !(Objects.isNull(this.errors) || this.errors.isEmpty());
    }

    @Override
    public List<String> getErrors() {
        return errors;
    }

    @Override
    public void addError(String error) {
        if (Objects.isNull(this.errors)) {
            this.errors = new ArrayList();
        }
        this.errors.add(error);
    }

    @Override
    public void addErrors(List<String> errors) {
        this.errors = errors;
    }
}
