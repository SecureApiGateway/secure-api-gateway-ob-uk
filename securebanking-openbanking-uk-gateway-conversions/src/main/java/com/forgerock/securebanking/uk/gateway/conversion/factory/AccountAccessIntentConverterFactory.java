package com.forgerock.securebanking.uk.gateway.conversion.factory;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.converters.AccountAccessIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AccountAccessIntentConverterFactory {
    private static final Logger logger = LoggerFactory.getLogger(AccountAccessIntentConverterFactory.class);

    public static GenericIntentConverter getConverter(OBVersion version) {
        switch (version) {
            case v3_1_1:
            case v3_1_2:
            case v3_1_3:
            case v3_1_4:
            case v3_1_5:
            case v3_1_6:
            case v3_1_7:
            case v3_1_8:
                return new AccountAccessIntentConverter();
            default: {
                String message = String.format("Couldn't find the %s converter for version %s", IntentType.ACCOUNT_ACCESS_CONSENT.name(), version.name());
                logger.error(message);
                throw new RuntimeException(message);
            }
        }
    }
}
