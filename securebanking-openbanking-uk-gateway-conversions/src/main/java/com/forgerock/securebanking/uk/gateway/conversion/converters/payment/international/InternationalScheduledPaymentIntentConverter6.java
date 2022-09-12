package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteInternationalScheduledConsentResponse6;

public class InternationalScheduledPaymentIntentConverter6 extends GenericIntentConverter<OBWriteInternationalScheduledConsentResponse6> {
    private static final Logger logger = LoggerFactory.getLogger(InternationalScheduledPaymentIntentConverter6.class);

    public InternationalScheduledPaymentIntentConverter6() {
        super(InternationalScheduledPaymentIntentConverter6::convert);
    }

    private static OBWriteInternationalScheduledConsentResponse6 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteInternationalScheduledConsentResponse6.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
