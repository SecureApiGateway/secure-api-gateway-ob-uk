package com.forgerock.securebanking.uk.gateway.conversion.factory.payment;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international.InternationalPaymentIntentConverter5;
import com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international.InternationalPaymentIntentConverter6;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InternationalPaymentIntentConverterFactory {
    private static final Logger logger = LoggerFactory.getLogger(InternationalPaymentIntentConverterFactory.class);

    public static GenericIntentConverter getConverter(OBVersion version) {
        switch (version) {
            case v3_1_4: // OBWriteInternationalConsentResponse5
                return new InternationalPaymentIntentConverter5();
            case v3_1_5: // OBWriteInternationalConsentResponse6
            case v3_1_6:
            case v3_1_7:
            case v3_1_8:
            case v3_1_9:
            case v3_1_10:
                return new InternationalPaymentIntentConverter6();
            default: {
                String message = String.format("Couldn't find the %s converter for version %s", IntentType.PAYMENT_INTERNATIONAL_CONSENT.name(), version.name());
                logger.error(message);
                throw new RuntimeException(message);
            }
        }
    }
}
