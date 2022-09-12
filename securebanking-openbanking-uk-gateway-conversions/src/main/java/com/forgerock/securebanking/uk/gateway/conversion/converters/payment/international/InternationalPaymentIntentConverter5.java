package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteInternationalConsentResponse5;

public class InternationalPaymentIntentConverter5 extends GenericIntentConverter<OBWriteInternationalConsentResponse5> {
    private static final Logger logger = LoggerFactory.getLogger(InternationalPaymentIntentConverter5.class);

    public InternationalPaymentIntentConverter5() {
        super(InternationalPaymentIntentConverter5::convert);
    }

    private static OBWriteInternationalConsentResponse5 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteInternationalConsentResponse5.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
