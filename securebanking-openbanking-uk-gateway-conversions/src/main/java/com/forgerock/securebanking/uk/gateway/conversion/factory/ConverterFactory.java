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
package com.forgerock.securebanking.uk.gateway.conversion.factory;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.converters.AccountAccessIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ConverterFactory {

    private static final Logger logger = LoggerFactory.getLogger(ConverterFactory.class);

    public static GenericIntentConverter getConverter(IntentType intentType) {
        switch (intentType) {
            case ACCOUNT_ACCESS_CONSENT -> {
                return new AccountAccessIntentConverter();
            }
            case PAYMENT_DOMESTIC_CONSENT -> {
                return null;
            }
            case PAYMENT_DOMESTIC_SCHEDULED_CONSENT -> {
                return null;
            }
            case PAYMENT_DOMESTIC_STANDING_ORDERS_CONSENT -> {
                return null;
            }
            case PAYMENT_INTERNATIONAL_CONSENT -> {
                return null;
            }
            case PAYMENT_INTERNATIONAL_SCHEDULED_CONSENT -> {
                return null;
            }
            case PAYMENT_INTERNATIONAL_STANDING_ORDERS_CONSENT -> {
                return null;
            }
            case PAYMENT_FILE_CONSENT -> {
                return null;
            }
            case FUNDS_CONFIRMATION_CONSENT -> {
                return null;
            }
            default -> {
                logger.warn("Couldn't identify the intent type" + intentType);
                throw new RuntimeException("Couldn't identify the intent type" + intentType);
            }
        }
    }
}
