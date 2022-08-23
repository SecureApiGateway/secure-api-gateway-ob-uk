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
package com.forgerock.securebanking.uk.gateway.utils;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.utils.jackson.GenericConverterMapper;

import java.util.HashMap;
import java.util.Map;

/**
 * Util to identify the IntentType by 'payload.Data.ConsentId'
 */
public class IntentTypeUtils {
    /**
     * Identify the intent type {@link IntentType}
     * @param payload the json intent
     * @return the {@link IntentType} if has be found
     * @throws Exception
     */
    public static IntentType getIntentType(String payload) throws Exception {
        HashMap map = GenericConverterMapper.getMapper().readValue(payload, HashMap.class);
        if (map.get("Data") == null) {
            throw new Exception("The entity doesn't have 'Data' Object to identify the intent type");
        }
        String consentId = ((Map<String, String>) map.get("Data")).get("ConsentId");
        if (consentId == null) {
            throw new Exception("The entity doesn't have 'ConsentId' to identify the intent type");
        }
        IntentType intentType = IntentType.identify(consentId);
        if (intentType == null) {
            throw new Exception("It cannot be possible to identify the intent type with the consentId " + consentId);
        }
        return intentType;
    }
}
