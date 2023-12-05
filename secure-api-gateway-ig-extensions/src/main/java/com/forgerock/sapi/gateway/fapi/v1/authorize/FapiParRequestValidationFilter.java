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
package com.forgerock.sapi.gateway.fapi.v1.authorize;

import java.io.IOException;

import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

/**
 * Validates that a request made to the OAuth2.0 /par (Pushed Authorization Request) endpoint is FAPI compliant.
 *
 * For /par requests, the request JWT is supplied as an HTTP Form parameter.
 *
 * OAuth 2.0 Pushed Authorization Request spec: https://datatracker.ietf.org/doc/html/rfc9126
 */
public class FapiParRequestValidationFilter extends BaseFapiAuthorizeRequestValidationFilter {
    @Override
    protected Promise<String, NeverThrowsException> getParamFromRequest(Request request, String paramName) {
        return request.getEntity().getFormAsync()
                .then(form -> form.getFirst(paramName))
                .thenCatch(ioe -> {
                    logger.warn("Failed to extract data from /par request due to exception", ioe);
                    return null;
                });
    }

    @Override
    protected void removeStateParamFromRequest(Request request) {
        try {
            final Form form = request.getEntity().getForm();
            form.remove("state");
            request.setEntity(form);
        } catch (IOException e) {
            logger.warn("Failed to remove state param from /par request form due to exception", e);
        }
    }

    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new FapiParRequestValidationFilter();
        }
    }
}
