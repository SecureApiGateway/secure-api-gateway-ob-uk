package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.vrp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.vrp.OBDomesticVRPConsentResponse;

public class DomesticVrpPaymentIntentConverter extends GenericIntentConverter<OBDomesticVRPConsentResponse> {

    private static final Logger logger = LoggerFactory.getLogger(DomesticVrpPaymentIntentConverter.class);

    public DomesticVrpPaymentIntentConverter() {
        super(DomesticVrpPaymentIntentConverter::convert);
    }

    private static OBDomesticVRPConsentResponse convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBDomesticVRPConsentResponse.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
