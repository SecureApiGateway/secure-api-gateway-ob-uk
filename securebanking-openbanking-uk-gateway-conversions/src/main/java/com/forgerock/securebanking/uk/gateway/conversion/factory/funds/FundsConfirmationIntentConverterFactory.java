package com.forgerock.securebanking.uk.gateway.conversion.factory.funds;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.converters.funds.FundsConfirmationIntentConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FundsConfirmationIntentConverterFactory {

    private static final Logger logger = LoggerFactory.getLogger(FundsConfirmationIntentConverterFactory.class);

    public static GenericIntentConverter getConverter(OBVersion version) {
        switch (version) {
            case v3_1_2: // OBFundsConfirmationConsentResponse1
            case v3_1_3:
            case v3_1_4:
            case v3_1_5:
            case v3_1_6:
            case v3_1_7:
            case v3_1_8:
            case v3_1_9:
            case v3_1_10:
                return new FundsConfirmationIntentConverter();
            default: {
                String message = String.format("Couldn't find the %s converter for version %s", IntentType.FUNDS_CONFIRMATION_CONSENT.name(), version.name());
                logger.error(message);
                throw new RuntimeException(message);
            }
        }
    }
}
