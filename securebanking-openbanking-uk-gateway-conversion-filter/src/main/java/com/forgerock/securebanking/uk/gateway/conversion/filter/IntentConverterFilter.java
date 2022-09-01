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
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.factory.ConverterFactory;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import com.google.common.base.Enums;
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
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.json.JsonValueFunctions.enumConstant;

/**
 * Filter to convert IDM json intent objects to OB data model objects.
 *
 * This filter must have received {@code intentType} as required to identify the intent type {@link IntentType#toString()} to instance the converter,
 * the {@code intentContent} as optional of string representation of a json intent to be converter to OB data model object,
 * if 'intentContent' isn't provided the filter will get the intent content in string format from the entity request.
 * Failures from the `Converter instance` is either a {@link RuntimeException} that will catch to build a {@link ResponseException}.
 *
 * Configuration options:
 *
 * <pre>
 * {@code {
 *      "name": "IntentConverterFilter"
 *      "type": "IntentConverterFilter",
 *      "config": {
 *         "intentType"   IntentType#toString()    [REQUIRED - (ItIdentifies the consent type by enum name (ACCOUNT_ACCESS_CONSENT, PAYMENT_INTERNATIONAL_CONSENT... ]
 *         "payloadFrom"  MessageType              [REQUIRED - Indicates where need to be get the JSON payload of intent object to be converted to OB Object, default REQUEST]
 *         "resultTo"     List<MessageType>        [OPTIONAL - Indicates where will set the conversion result. Default RESPONSE.]
 *      }
 *  }
 *  }
 * </pre>
 * <p>Example</p>
 * <pre>
 * {@code {
 *      "name": "IntentConverterFilter-accessAccountConsent"
 *      "type": "IntentConverterFilter",
 *      "config": {
 *         "intentType": "ACCOUNT_ACCESS_CONSENT",
 *         "payloadFrom":"REQUEST",
 *         "resultTo": ["RESPONSE"]
 *      }
 *  }
 *  }
 * </pre>
 */
public class IntentConverterFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(IntentConverterFilter.class);

    public static final String APPLICATION_JSON_CHARSET_UTF_8 = "application/json; charset=UTF-8";

    private final IntentType intentType;
    public static final String CONFIG_FIELD_INTENT_TYPE = "intentType";
    private final MessageType payloadFrom;
    public static final String CONFIG_FIELD_PAYLOAD_FROM = "payloadFrom";
    private final List<MessageType> resultTo;
    public static final String CONFIG_FIELD_RESULT_TO = "resultTo";

    private static final ObjectMapper MAPPER = GenericConverterMapper.getMapper();

    public IntentConverterFilter(final IntentType intentType, final MessageType payloadFrom) {
        this(intentType, payloadFrom, List.of(MessageType.RESPONSE));
    }

    public IntentConverterFilter(final IntentType intentType, final MessageType payloadFrom, final List<MessageType> resultTo) {
        this.intentType = intentType;
        this.payloadFrom = payloadFrom;
        this.resultTo = resultTo;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        try {
            if (logger.isInfoEnabled()) {
                printFilterInfo();
            }
            String jsonPayload = getEntity(context, request, next);

            Object objectMapped = convert(jsonPayload);

            byte[] serialised = toBytes(objectMapped);

            return processResult(serialised, context, request, next);
        } catch (Exception e) {
            logger.error("Conversion to OB Object filter Error\n", e);
            ResponseException responseException = new ResponseException(e.getMessage(), e);
            // Overriding the internal server error status to bad request
            responseException.getResponse().setStatus(Status.BAD_REQUEST);
            return newResponsePromise(responseException.getResponse());
        }
    }

    /** Creates and initializes a ConversionFilter in a heap environment. */
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() {
            IntentType intentType = config.get(CONFIG_FIELD_INTENT_TYPE)
                    .required()
                    .as(enumConstant(IntentType.class));
            logger.trace("intentType = {}", intentType);
            MessageType payloadFrom = config.get(CONFIG_FIELD_PAYLOAD_FROM)
                    .required()
                    .defaultTo(MessageType.REQUEST.toString())
                    .as(enumConstant(MessageType.class));
            logger.trace("payload From {}", payloadFrom);
            List<MessageType> payloadTo = config.get(CONFIG_FIELD_RESULT_TO)
                    .defaultTo(List.of(MessageType.RESPONSE.toString()))
                    .as(messageTypeList());
            return new IntentConverterFilter(intentType, payloadFrom, payloadTo);
        }
    }

    private static Function<JsonValue, List<MessageType>, JsonValueException> messageTypeList() {
        return jsonValue -> {
            List<String> jsonValueList = jsonValue.asList(String.class);
            List<MessageType> resultList = new ArrayList<>();
            for (String value : jsonValueList) {
                if (!Enums.getIfPresent(MessageType.class, value).isPresent()) {
                    String message = String.format("Configuration 'resultTo' %s list contains not supported values," +
                            " all configuration values should be a MessageType values.", jsonValueList );
                    logger.error(message);
                    throw new JsonValueException(jsonValue, message);
                }
                resultList.add(MessageType.valueOf(value));
            }
            return resultList;
        };
    }

    private String getEntity(Context context, Request request, Handler next) throws IOException, InterruptedException {
        logger.trace("Payload from {}", this.payloadFrom);
        if (payloadFrom.equals(MessageType.RESPONSE)) {
            return getEntity(next.handle(context, request).getOrThrow());
        }
        return getEntity(request);
    }

    private String getEntity(final Message<?> message) throws IOException {
        return message.getEntity().getString();
    }

    private Object convert(String jsonPayload) {
        return ConverterFactory.getConverter(intentType).convertFromJsonString(jsonPayload);
    }

    private byte[] toBytes(Object objectMapped) throws JsonProcessingException {
        return MAPPER.writeValueAsBytes(objectMapped);
    }

    private Promise<Response, NeverThrowsException> processResult(byte[] serialised, Context context, Request request, Handler next) {
        logger.trace("Set the result to {}", resultTo);
        // add the result to the request overwriting the entity
        if (resultTo.contains(MessageType.REQUEST)) {
            request.setEntity(serialised);
        }
        // add the entity to the response
        if (resultTo.contains(MessageType.RESPONSE)) {
            return next.handle(context, request)
                    .thenOnResult(response -> {
                        response.setEntity(serialised);
                        response.setStatus(Status.OK);
                        response.getHeaders().put(ContentTypeHeader.NAME, APPLICATION_JSON_CHARSET_UTF_8);
                    });
        }
        return next.handle(context, request);
    }

    private void printFilterInfo() {
        logger.info("Filter {}", this.getClass().getSimpleName());
        logger.info("Conversion of Intent type {}", intentType);
        logger.info("Payload from {}", payloadFrom);
        logger.info("Set result of conversion to {}", resultTo);
    }
}
