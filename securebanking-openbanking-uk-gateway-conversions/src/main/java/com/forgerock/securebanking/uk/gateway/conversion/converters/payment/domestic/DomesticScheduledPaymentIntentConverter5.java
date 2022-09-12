package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticScheduledConsentResponse5;

public class DomesticScheduledPaymentIntentConverter5 extends GenericIntentConverter<OBWriteDomesticScheduledConsentResponse5> {
    private static final Logger logger = LoggerFactory.getLogger(DomesticPaymentIntentConverter5.class);

    public DomesticScheduledPaymentIntentConverter5() {
        super(DomesticScheduledPaymentIntentConverter5::convert);
    }

    private static OBWriteDomesticScheduledConsentResponse5 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteDomesticScheduledConsentResponse5.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
