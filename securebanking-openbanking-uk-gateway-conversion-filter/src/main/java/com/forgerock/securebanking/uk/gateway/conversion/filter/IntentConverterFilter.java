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

import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.factory.ConverterFactory;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.ResponseException;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.services.context.Context;
import org.forgerock.util.Function;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.PromiseImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

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
 *      "type": "ConversionToOBObjectFilter",
 *      "config": {
 *         "intentType"     IntentType#toString()    [REQUIRED - (ItIdentifies the consent type by enum name (ACCOUNT_ACCESS_CONSENT, PAYMENT_INTERNATIONAL_CONSENT... ]
 *         "intentContent"  string                   [OPTIONAL - String representation of json intent object to be converted to OB Object]
 *      }
 *  }
 *  }
 * </pre>
 */
public class IntentConverterFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(IntentConverterFilter.class);

    private final IntentType intentType;
    private final String intentContent;

    public IntentConverterFilter(final IntentType intentType, final String stringObject) {
        this.intentType = intentType;
        this.intentContent = stringObject;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        // To be able to compile with the generics type erasure, we have to get the help of another PromiseImpl.
        PromiseImpl<Set<String>, ResponseException> promise = PromiseImpl.create();
        String entity = intentContent;
        try {
            if (entity == null) {
                entity = request.getEntity().getString();
            }
            Object converted = ConverterFactory.getConverter(intentType).convertFromJsonString(entity);
            request.setEntity(converted);
            // add the entity to the response
            return next.handle(context, request)
                    .thenOnResult(response -> {
                        response.setEntity(converted);
                        response.setStatus(Status.OK);
                    });
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
            IntentType intentType = config.get("intentType")
                    .required()
                    .as(enumConstant(IntentType.class));
            String intentContent = config.get("intentContent").asString();
            return new IntentConverterFilter(intentType, intentContent != null ? intentContent : null);
        }
    }
}
