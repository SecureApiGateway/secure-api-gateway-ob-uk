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
package com.forgerock.sapi.gateway.trusteddirectories;

import static org.forgerock.openig.util.JsonValues.javaDuration;

import java.time.Duration;

import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;

import com.forgerock.sapi.gateway.jwks.cache.caffeine.CaffeineCache;

public class TrustedDirectoryServiceHeaplet extends GenericHeaplet {

    private final Boolean DEFAULT_IG_TEST_DIRECTORY_ENABLED = false;

    @Override
    public Object create() throws HeapException {
        return createTrustedDirectoryService();
    }

    private Object createTrustedDirectoryService() {
        final Boolean enableIGTestTrustedDirectory = config.get("enableIGTestTrustedDirectory")
                .as(evaluatedWithHeapProperties())
                .defaultTo(DEFAULT_IG_TEST_DIRECTORY_ENABLED)
                .asBoolean();
        final String testDirectoryFQDN = config.get("testDirectoryFQDN")
                .as(evaluatedWithHeapProperties())
                .defaultTo(null)
                .asString();

        return new TrustedDirectoryServiceStatic(enableIGTestTrustedDirectory, testDirectoryFQDN);
    }
}
