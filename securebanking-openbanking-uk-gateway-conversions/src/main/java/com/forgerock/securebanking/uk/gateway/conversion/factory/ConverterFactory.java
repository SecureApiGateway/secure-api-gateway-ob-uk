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

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.factory.account.AccountAccessIntentConverterFactory;
import com.forgerock.securebanking.uk.gateway.conversion.factory.funds.FundsConfirmationIntentConverterFactory;
import com.forgerock.securebanking.uk.gateway.conversion.factory.payment.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory to instance the specific converter implementation by version {@link OBVersion}
 */
public final class ConverterFactory {

    private static final Logger logger = LoggerFactory.getLogger(ConverterFactory.class);

    public static GenericIntentConverter getConverter(IntentType intentType, OBVersion obVersion) {
        switch (intentType) {
            case ACCOUNT_ACCESS_CONSENT: {
                return AccountAccessIntentConverterFactory.getConverter(obVersion);
            }
            case PAYMENT_DOMESTIC_CONSENT: {
                return DomesticPaymentIntentConverterFactory.getConverter(obVersion);
            }
            case PAYMENT_DOMESTIC_SCHEDULED_CONSENT: {
                return DomesticScheduledPaymentIntentConverterFactory.getConverter(obVersion);
            }
            case PAYMENT_DOMESTIC_STANDING_ORDERS_CONSENT: {
                return DomesticStandingOrderIntentConverterFactory.getConverter(obVersion);
            }
            case PAYMENT_INTERNATIONAL_CONSENT: {
                return InternationalPaymentIntentConverterFactory.getConverter(obVersion);
            }
            case PAYMENT_INTERNATIONAL_SCHEDULED_CONSENT: {
                return InternationalScheduledPaymentIntentConverterFactory.getConverter(obVersion);
            }
            case PAYMENT_INTERNATIONAL_STANDING_ORDERS_CONSENT: {
                return InternationalStandingOrderIntentConverterFactory.getConverter(obVersion);
            }
            case PAYMENT_FILE_CONSENT: {
                return FilePaymentIntentConverterFactory.getConverter(obVersion);
            }
            case FUNDS_CONFIRMATION_CONSENT: {
                return FundsConfirmationIntentConverterFactory.getConverter(obVersion);
            }
            default: {
                String message = String.format("Couldn't identify the intent type %s", intentType);
                logger.error(message);
                throw new RuntimeException(message);
            }
        }
    }
}