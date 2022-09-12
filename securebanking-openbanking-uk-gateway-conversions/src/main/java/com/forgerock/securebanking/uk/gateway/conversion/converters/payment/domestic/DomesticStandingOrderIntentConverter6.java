package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticStandingOrderConsentResponse6;

public class DomesticStandingOrderIntentConverter6 extends GenericIntentConverter<OBWriteDomesticStandingOrderConsentResponse6> {

    private static final Logger logger = LoggerFactory.getLogger(DomesticStandingOrderIntentConverter6.class);

    public DomesticStandingOrderIntentConverter6() {
        super(DomesticStandingOrderIntentConverter6::convert);
    }

    private static OBWriteDomesticStandingOrderConsentResponse6 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteDomesticStandingOrderConsentResponse6.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
