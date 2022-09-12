package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.file;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.org.openbanking.datamodel.payment.OBWriteFileConsentResponse4;

public class FilePaymentIntentConverter4 extends GenericIntentConverter<OBWriteFileConsentResponse4> {

    private static final Logger logger = LoggerFactory.getLogger(FilePaymentIntentConverter4.class);

    public FilePaymentIntentConverter4() {
        super(FilePaymentIntentConverter4::convert);
    }

    private static OBWriteFileConsentResponse4 convert(String jsonString) {
        try {
            logger.debug("Payload to be converted\n {}", jsonString);
            return GenericConverterMapper.getMapper().readValue(jsonString, OBWriteFileConsentResponse4.class);
        } catch (JsonProcessingException e) {
            logger.trace("The following RuntimeException was caught : ", e);
            throw new RuntimeException(e);
        }
    }
}
