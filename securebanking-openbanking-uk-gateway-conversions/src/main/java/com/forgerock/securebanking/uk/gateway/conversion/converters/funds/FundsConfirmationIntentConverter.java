package com.forgerock.securebanking.uk.gateway.conversion.converters.funds;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.fund.OBFundsConfirmationConsentResponse1;

public class FundsConfirmationIntentConverter extends GenericIntentConverter<OBFundsConfirmationConsentResponse1> {

    private static final Logger logger = LoggerFactory.getLogger(FundsConfirmationIntentConverter.class);

    public FundsConfirmationIntentConverter() {
        super(FundsConfirmationIntentConverter::convert);
    }

    private static OBFundsConfirmationConsentResponse1 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBFundsConfirmationConsentResponse1.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
