/*
 * Copyright © 2020-2022 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.securebanking.uk.gateway.conversion.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.factory.ConverterFactory;
import com.forgerock.securebanking.uk.gateway.utils.ApiVersionUtils;
import com.forgerock.securebanking.uk.gateway.utils.jackson.GenericConverterMapper;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.*;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.util.MessageType;
import org.forgerock.services.context.Context;
import org.forgerock.util.Function;
import org.forgerock.util.Strings;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

import static com.forgerock.securebanking.uk.gateway.utils.IntentTypeUtils.getIntentType;
import static org.forgerock.http.protocol.Entity.APPLICATION_JSON_CHARSET_UTF_8;
import static org.forgerock.json.JsonValueFunctions.enumConstant;
import static org.forgerock.util.promise.Promises.newResultPromise;

/**
 * Filter to convert IDM json intent objects to OB data model objects.
 *
 * This filter must have received {@link  MessageType} as required to get the entity  to instance the converter and know the {@link MessageImpl} to be updated<br/>
 * Failures from the `Converter instance` is either a {@link RuntimeException} that will catch to build a {@link ResponseException}.
 *
 * Configuration options:
 *
 * <pre>
 * {@code {
 *      "name": "IntentConverterFilter-name"
 *      "type": "IntentConverterFilter",
 *      "config": {
 *         "messageType"  MessageType   [REQUIRED - The type of message for which to convert the entity, Must be either "REQUEST" or "RESPONSE"]
 *      }
 *  }
 *  }
 * </pre>
 * <p>Examples</p>
 * <pre>
 * {@code {
 *      "name": "IntentConverterFilter-name"
 *      "type": "IntentConverterFilter",
 *      "config": {
 *         "messageType: "request"
 *      }
 *  }
 *  }
 * </pre>
 * <pre>
 *  {@code {
 *       "name": "IntentConverterFilter-name"
 *       "type": "IntentConverterFilter",
 *       "config": {
 *          "messageType: "response"
 *       }
 *   }
 *   }
 *  </pre>
 */
public class IntentConverterFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(IntentConverterFilter.class);

    private final MessageType messageType;
    private static final ObjectMapper MAPPER = GenericConverterMapper.getMapper();

    /**
     * Constructor
     * @param messageType
     */
    public IntentConverterFilter(final MessageType messageType) {
        this.messageType = messageType;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        if (logger.isInfoEnabled()) {
            printFilterInfo();
        }

        // MessageType.REQUEST
        if (messageType.equals(MessageType.REQUEST)) {
            try {
                process(request, request.getUri().asURI());
                return next.handle(context, request);
            } catch (Exception e) {
                return newResultPromise(badRequestError(e));
            }
        }

        // MessageType.RESPONSE
        return next.handle(context, request)
                .then(response ->
                        {
                            try {
                                if(response.getStatus().isSuccessful()) {
                                    process(response, request.getUri().asURI());
                                }
                            } catch (Exception ex) {
                                return badRequestError(ex);
                            }
                            return response;
                        }
                );
    }

    /**
     * Convert the message
     * @param message
     *         a {@link MessageImpl} to be processed
     * @param uri
     *         the request URI to extract the api version to instance the proper converter
     * @return a {@link Promise} to be passed the next handle
     */
    private void process(MessageImpl message, URI uri) throws Exception {
        String jsonPayload = getEntity(message);
        OBVersion obVersion = ApiVersionUtils.getOBVersion(uri);
        Object objectMapped = convert(getIntentType(jsonPayload), jsonPayload, obVersion);
        logger.info("Result object {}", objectMapped.getClass().getSimpleName());
        logger.debug("objectMapped {}", objectMapped);
        // set the converted object as entity
        message.setEntity(toBytes(objectMapped));
        if (!message.getHeaders().containsKey(ContentTypeHeader.NAME)) {
            message.getHeaders().put(ContentTypeHeader.NAME, APPLICATION_JSON_CHARSET_UTF_8);
        }
    }

    private Response badRequestError(Exception e) {
        logger.error("Conversion to OB Object filter Error\n", e);
        return new Response(Status.BAD_REQUEST)
                .setCause(e)
                .setEntity(e.getMessage().getBytes());
    }

    /**
     * Extract the entity form {@link MessageImpl} to be processed
     * @param message a {@link MessageImpl} ({@link Request} or {@link Response})
     * @return the entity string
     * @throws Exception
     */
    private String getEntity(final MessageImpl message) throws Exception {
        String jsonPayload = message.getEntity().getString();
        logger.debug("Payload from {}.entity {}", messageType.toString().toLowerCase(), jsonPayload);
        if (Strings.isNullOrEmpty(jsonPayload)) {
            throw new Exception("The entity to be converted should not be null");
        }
        return jsonPayload;
    }

    /**
     * Call the converter factory to convert the payload
     * @param intentType a {@link IntentType}
     * @param jsonPayload the payload to be converted
     * @param obVersion  a {@link OBVersion}
     * @return the converted object
     */
    private Object convert(IntentType intentType, String jsonPayload, OBVersion obVersion) {
        logger.info("Conversion of Intent type {}", intentType);
        return ConverterFactory.getConverter(intentType, obVersion).convertFromJsonString(jsonPayload);
    }

    /**
     * Serialize any Java value as a byte array
     * @param objectMapped java value to be serialize
     * @return byte array serialization result
     * @throws JsonProcessingException
     */
    private byte[] toBytes(Object objectMapped) throws JsonProcessingException {
        return MAPPER.writeValueAsBytes(objectMapped);
    }


    private void printFilterInfo() {
        logger.info("Filter {}", this.getClass().getSimpleName());
        logger.info("Set result of conversion to {}", messageType.name());
    }

    /** Creates and initializes a IntentConverterFilter in a heap environment. */
    public static class Heaplet extends GenericHeaplet {
        public static final String CONFIG_FIELD_MESSAGE_TYPE = "messageType";

        @Override
        public Object create() {
            final MessageType messageType = config.get(CONFIG_FIELD_MESSAGE_TYPE)
                    .required()
                    .defaultTo(MessageType.REQUEST.toString())
                    .as(toUpperCase())
                    .as(enumConstant(MessageType.class));
            return new IntentConverterFilter(messageType);
        }

        private static Function<JsonValue, JsonValue, JsonValueException> toUpperCase() {
            return jsonValue -> new JsonValue(jsonValue.asString().toUpperCase());
        }
    }
}
