package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticStandingOrderConsentResponse5;

public class DomesticStandingOrderIntentConverter5 extends GenericIntentConverter<OBWriteDomesticStandingOrderConsentResponse5> {

    private static final Logger logger = LoggerFactory.getLogger(DomesticStandingOrderIntentConverter5.class);

    public DomesticStandingOrderIntentConverter5() {
        super(DomesticStandingOrderIntentConverter5::convert);
    }

    private static OBWriteDomesticStandingOrderConsentResponse5 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteDomesticStandingOrderConsentResponse5.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
