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
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import com.forgerock.securebanking.uk.gateway.utils.ApiVersionUtils;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Enums;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.*;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.el.Bindings;
import org.forgerock.openig.el.Expression;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.util.MessageType;
import org.forgerock.services.context.Context;
import org.forgerock.util.Function;
import org.forgerock.util.Strings;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.forgerock.http.protocol.Entity.APPLICATION_JSON_CHARSET_UTF_8;
import static org.forgerock.json.JsonValueFunctions.enumConstant;
import static org.forgerock.openig.el.Bindings.bindings;
import static org.forgerock.openig.util.AsyncFunctions.asyncResultHandler;
import static org.forgerock.util.promise.NeverThrowsException.neverThrown;
import static org.forgerock.util.promise.Promises.newResultPromise;

/**
 * Filter to convert IDM json intent objects to OB data model objects.
 *
 * This filter must have received {@code intentType} as required to identify the intent type {@link IntentType#toString()} to instance the converter<br/>
 * Failures from the `Converter instance` is either a {@link RuntimeException} that will catch to build a {@link ResponseException}.
 *
 * Configuration options:
 *
 * <pre>
 * {@code {
 *      "name": "IntentConverterFilter-name"
 *      "type": "IntentConverterFilter",
 *      "config": {
 *         "messageType"  MessageType              [REQUIRED - The type of message for which to convert the entity, Must be either "REQUEST" or "RESPONSE"]
 *         "entity"       Expression<String>       [OPTIONAL - A jsonPayload content to be converted in string format. Default : not replaced.]
 *         "resultTo"     List<MessageType>        [OPTIONAL - Indicates where will set the conversion result. Must be either "REQUEST" or "RESPONSE". Default REQUEST.]
 *      }
 *  }
 *  }
 * </pre>
 * <p>Example</p>
 * <pre>
 * {@code {
 *      "name": "IntentConverterFilter-name"
 *      "type": "IntentConverterFilter",
 *      "config": {
 *         "messageType: "request",
 *         "entity": "#{request.entity.string}",
 *         "resultTo": ["REQUEST", "RESPONSE],
 *      }
 *  }
 *  }
 * </pre>
 */
public class IntentConverterFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(IntentConverterFilter.class);

    private final MessageType messageType;
    private final List<MessageType> resultTo;
    private final Expression<String> entity;
    private static final ObjectMapper MAPPER = GenericConverterMapper.getMapper();

    /**
     * Constructor
     * @param messageType
     * @param entity
     * @param resultTo
     */
    public IntentConverterFilter(final MessageType messageType, final Expression<String> entity, final List<MessageType> resultTo) {
        this.messageType = messageType;
        this.entity = entity;
        this.resultTo = resultTo;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        if (logger.isInfoEnabled()) {
            printFilterInfo();
        }

        if (messageType.equals(MessageType.REQUEST)) {
            return next.handle(context, request).thenAsync(response -> processRequest(request, response, bindings(context, request)));
        }

        // messageType RESPONSE
        return next.handle(context, request)
                .thenAsync(asyncResultHandler(response -> processResponse(request, response, bindings(context, request, response))));
    }

    private Promise<Void, NeverThrowsException> processResponse(final Request request, final Response response, final Bindings bindings) {
        try {
            process(request, response, getEntity(response, bindings));
            return newResultPromise(null);
        } catch (Exception e) {
            badRequestError(response, e);
            return newResultPromise(null);
        }
    }

    private Promise<Response, NeverThrowsException> processRequest(final Request request, final Response response, final Bindings bindings) {
        try {
            process(request, response, getEntity(request, bindings));
            return newResultPromise(response);
        } catch (Exception e) {
            badRequestError(response, e);
            return newResultPromise(response);
        }
    }

    private void badRequestError(Response response, Exception e) {
        logger.error("Conversion to OB Object filter Error\n", e);
        response.setCause(e);
        response.setEntity(e.getMessage().getBytes());
        response.setStatus(Status.BAD_REQUEST);
    }

    private void process(Request request, Response response, String entity) throws Exception {
        String jsonPayload = entity;
        if (Strings.isNullOrEmpty(jsonPayload)) {
            throw new Exception("The entity to be converted should not be null");
        }
        OBVersion obVersion = ApiVersionUtils.getOBVersion(request.getUri().asURI());
        Object objectMapped = convert(getIntentType(jsonPayload), jsonPayload, obVersion);
        logger.info("Result object {}", objectMapped.getClass().getSimpleName());
        logger.debug("objectMapped {}", objectMapped);
        if (resultTo.contains(MessageType.REQUEST)) {
            setEntity(request, toBytes(objectMapped));
        }
        if (resultTo.contains(MessageType.RESPONSE)) {
            setEntity(response, toBytes(objectMapped));
        }
    }

    private void setEntity(final Message<?> message, byte[] content) {
        message.setEntity(content);
        if (!message.getHeaders().containsKey(ContentTypeHeader.NAME)) {
            message.getHeaders().put(ContentTypeHeader.NAME, APPLICATION_JSON_CHARSET_UTF_8);
        }
    }

    private IntentType getIntentType(String payload) throws Exception {

        Map<String, Object> map = GenericConverterMapper.getMapper().readValue(payload, HashMap.class);
        if (map.get("Data") == null) {
            throw new Exception("The entity doesn't have 'Data' Object to identify the intent type");
        }
        String consentId = ((Map<String, String>) map.get("Data")).get("ConsentId");
        if (consentId == null) {
            throw new Exception("The entity doesn't have 'ConsentId' to identify the intent type");
        }
        IntentType intentType = IntentType.identify(consentId);
        if (intentType == null) {
            throw new Exception("It cannot be possible to identify the intent type with the consentId " + consentId);
        }
        return intentType;
    }

    private String getEntity(final Message<?> message, final Bindings bindings) throws Exception {
        if (entity != null) {
            logger.debug("Payload from optional entity {}", entity);
            return entity.eval(bindings);
        }
        String payload = message.getEntity().getString();
        logger.debug("Payload from {}.entity {}", messageType.toString().toLowerCase(), payload);
        return payload;
    }

    private Object convert(IntentType intentType, String jsonPayload, OBVersion obVersion) {
        logger.info("Conversion of Intent type {}", intentType);
        return ConverterFactory.getConverter(intentType, obVersion).convertFromJsonString(jsonPayload);
    }

    private byte[] toBytes(Object objectMapped) throws JsonProcessingException {
        return MAPPER.writeValueAsBytes(objectMapped);
    }

    private void printFilterInfo() {
        logger.info("Filter {}", this.getClass().getSimpleName());
        logger.info("Set result of conversion to {}", resultTo);
    }

    /** Creates and initializes a IntentConverterFilter in a heap environment. */
    public static class Heaplet extends GenericHeaplet {
        public static final String CONFIG_FIELD_MESSAGE_TYPE = "messageType";
        public static final String CONFIG_FIELD_ENTITY = "entity";
        public static final String CONFIG_FIELD_RESULT_TO = "resultTo";

        @Override
        public Object create() {
            final Expression<String> entity = config.get(CONFIG_FIELD_ENTITY).as(expression(String.class));
            final MessageType messageType = config.get(CONFIG_FIELD_MESSAGE_TYPE)
                    .required()
                    .defaultTo(MessageType.REQUEST.toString())
                    .as(toUpperCase())
                    .as(enumConstant(MessageType.class));
            final List<MessageType> payloadTo = config.get(CONFIG_FIELD_RESULT_TO)
                    .defaultTo(List.of(MessageType.REQUEST.toString()))
                    .as(messageTypeList());
            return new IntentConverterFilter(messageType, entity, payloadTo);
        }

        private static Function<JsonValue, List<MessageType>, JsonValueException> messageTypeList() {
            return jsonValue -> {
                List<String> jsonValueList = jsonValue.asList(String.class);
                List<MessageType> resultList = new ArrayList<>();
                for (String value : jsonValueList) {
                    if (!Enums.getIfPresent(MessageType.class, value.toUpperCase()).isPresent()) {
                        String message = String.format("Configuration field 'resultTo' contains not supported value '%s'," +
                                " all configuration values should be a MessageType values.", value);
                        logger.error(message);
                        throw new JsonValueException(jsonValue, message);
                    }
                    resultList.add(MessageType.valueOf(value.toUpperCase()));
                }
                return resultList;
            };
        }

        private static Function<JsonValue, JsonValue, JsonValueException> toUpperCase() {
            return jsonValue -> new JsonValue(jsonValue.asString().toUpperCase());
        }
    }
}
