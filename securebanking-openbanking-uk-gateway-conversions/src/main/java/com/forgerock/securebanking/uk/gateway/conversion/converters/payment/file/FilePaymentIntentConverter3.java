package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.file;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteFileConsentResponse3;

public class FilePaymentIntentConverter3 extends GenericIntentConverter<OBWriteFileConsentResponse3> {

    private static final Logger logger = LoggerFactory.getLogger(FilePaymentIntentConverter3.class);

    public FilePaymentIntentConverter3() {
        super(FilePaymentIntentConverter3::convert);
    }

    private static OBWriteFileConsentResponse3 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteFileConsentResponse3.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
