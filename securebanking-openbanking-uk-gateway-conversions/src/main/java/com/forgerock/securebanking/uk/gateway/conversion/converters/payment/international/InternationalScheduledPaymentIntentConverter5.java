package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteInternationalScheduledConsentResponse5;

public class InternationalScheduledPaymentIntentConverter5 extends GenericIntentConverter<OBWriteInternationalScheduledConsentResponse5> {
    private static final Logger logger = LoggerFactory.getLogger(InternationalScheduledPaymentIntentConverter5.class);

    public InternationalScheduledPaymentIntentConverter5() {
        super(InternationalScheduledPaymentIntentConverter5::convert);
    }

    private static OBWriteInternationalScheduledConsentResponse5 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteInternationalScheduledConsentResponse5.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
