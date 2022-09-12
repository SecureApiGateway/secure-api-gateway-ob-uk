package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteInternationalStandingOrderConsentResponse6;

public class InternationalStandingOrderIntentConverter6 extends GenericIntentConverter<OBWriteInternationalStandingOrderConsentResponse6> {

    private static final Logger logger = LoggerFactory.getLogger(InternationalStandingOrderIntentConverter6.class);

    public InternationalStandingOrderIntentConverter6() {
        super(InternationalStandingOrderIntentConverter6::convert);
    }

    private static OBWriteInternationalStandingOrderConsentResponse6 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteInternationalStandingOrderConsentResponse6.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
