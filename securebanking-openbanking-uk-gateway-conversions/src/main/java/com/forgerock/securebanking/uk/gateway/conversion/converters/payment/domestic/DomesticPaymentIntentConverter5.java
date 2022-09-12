package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticConsentResponse5;

public class DomesticPaymentIntentConverter5 extends GenericIntentConverter<OBWriteDomesticConsentResponse5> {
    private static final Logger logger = LoggerFactory.getLogger(DomesticPaymentIntentConverter5.class);

    public DomesticPaymentIntentConverter5() {
        super(DomesticPaymentIntentConverter5::convert);
    }

    private static OBWriteDomesticConsentResponse5 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteDomesticConsentResponse5.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }

}
