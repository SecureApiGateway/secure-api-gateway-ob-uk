package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteInternationalConsentResponse6;

public class InternationalPaymentIntentConverter6 extends GenericIntentConverter<OBWriteInternationalConsentResponse6> {
    private static final Logger logger = LoggerFactory.getLogger(InternationalPaymentIntentConverter6.class);

    public InternationalPaymentIntentConverter6() {
        super(InternationalPaymentIntentConverter6::convert);
    }

    private static OBWriteInternationalConsentResponse6 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteInternationalConsentResponse6.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
