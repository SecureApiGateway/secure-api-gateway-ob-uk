package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteInternationalStandingOrderConsentResponse7;

public class InternationalStandingOrderIntentConverter7 extends GenericIntentConverter<OBWriteInternationalStandingOrderConsentResponse7> {

    private static final Logger logger = LoggerFactory.getLogger(InternationalStandingOrderIntentConverter7.class);

    public InternationalStandingOrderIntentConverter7() {
        super(InternationalStandingOrderIntentConverter7::convert);
    }

    private static OBWriteInternationalStandingOrderConsentResponse7 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteInternationalStandingOrderConsentResponse7.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
