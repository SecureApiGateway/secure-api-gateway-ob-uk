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

import com.adelean.inject.resources.junit.jupiter.GivenTextResource;
import com.adelean.inject.resources.junit.jupiter.TestWithResources;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.uk.gateway.utils.jackson.GenericConverterMapper;
import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.el.Expression;
import org.forgerock.openig.handler.StaticResponseHandler;
import org.forgerock.openig.heap.EnvironmentHeap;
import org.forgerock.openig.heap.Name;
import org.forgerock.openig.util.MessageType;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;

import java.net.URI;
import java.util.stream.Stream;

import static com.forgerock.securebanking.uk.gateway.conversion.converters.account.AccountAccessIntentExpectedFactory.getExpectedOBReadConsentResponse1;
import static com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic.DomesticPaymentExpectedFactory.getExpectedOBWriteDomesticConsentResponse4;
import static com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic.DomesticPaymentExpectedFactory.getExpectedOBWriteDomesticConsentResponse5;
import static com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international.InternationalPaymentIntentExpectedFactory.getExpectedOBWriteInternationalConsentResponse5;
import static com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international.InternationalPaymentIntentExpectedFactory.getExpectedOBWriteInternationalConsentResponse6;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.*;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.forgerock.util.promise.Promises.newRuntimeExceptionPromise;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IntentConverterFilter}<br/>
 * By default the result will be in the request to be passed the next handler
 */
@TestWithResources
public class IntentConverterFilterTest {

    private static final URI _URI_v318 = URI.create("/rs/open-banking/v3.1.8/aisp/account-access-consents");
    private static final URI _URI_v314 = URI.create("/rs/open-banking/v3.1.4/aisp/account-access-consents");

    @GivenTextResource("accountAccessIntent.json")
    static String accountAccessIntent;
    @GivenTextResource("domesticPaymentIntent4.json")
    static String domesticPaymentIntent4;
    @GivenTextResource("domesticPaymentIntent5.json")
    static String domesticPaymentIntent5;
    @GivenTextResource("internationalPaymentIntent5.json")
    static String internationalPaymentIntent5;
    @GivenTextResource("internationalPaymentIntent6.json")
    static String internationalPaymentIntent6;
    @GivenTextResource("accountRequest.json") // to tests the intent type error
    static String accountRequest;

    @GivenTextResource("data-error.json") // to tests the intent type error
    static String dataError;

    @GivenTextResource("consentId-error.json") // to tests the intent type error
    static String consentIdError;

    @GivenTextResource("intent-type-error.json") // to tests the intent type error
    static String intentTypeError;

    private static Stream<Arguments> validArguments() throws JsonProcessingException {
        return Stream.of(
                arguments(
                        MessageType.REQUEST,
                        _URI_v318,
                        accountAccessIntent,
                        GenericConverterMapper.getMapper().writeValueAsString(getExpectedOBReadConsentResponse1())

                ),
                arguments(
                        MessageType.RESPONSE,
                        _URI_v318,
                        accountAccessIntent,
                        GenericConverterMapper.getMapper().writeValueAsString(getExpectedOBReadConsentResponse1())

                ),
                arguments(
                        MessageType.REQUEST,
                        _URI_v318,
                        domesticPaymentIntent5,
                        GenericConverterMapper.getMapper().writeValueAsString(getExpectedOBWriteDomesticConsentResponse5())

                ),
                arguments(
                        MessageType.RESPONSE,
                        _URI_v318,
                        internationalPaymentIntent6,
                        GenericConverterMapper.getMapper().writeValueAsString(getExpectedOBWriteInternationalConsentResponse6())

                ),
                arguments(
                        MessageType.REQUEST,
                        _URI_v314,
                        accountAccessIntent,
                        GenericConverterMapper.getMapper().writeValueAsString(getExpectedOBReadConsentResponse1())

                ),
                arguments(
                        MessageType.RESPONSE,
                        _URI_v314,
                        accountAccessIntent,
                        GenericConverterMapper.getMapper().writeValueAsString(getExpectedOBReadConsentResponse1())

                ),
                arguments(
                        MessageType.REQUEST,
                        _URI_v314,
                        domesticPaymentIntent4,
                        GenericConverterMapper.getMapper().writeValueAsString(getExpectedOBWriteDomesticConsentResponse4())

                ),
                arguments(
                        MessageType.RESPONSE,
                        _URI_v314,
                        internationalPaymentIntent5,
                        GenericConverterMapper.getMapper().writeValueAsString(getExpectedOBWriteInternationalConsentResponse5())

                )
        );
    }

    /**
     Case: The payload content is get from request
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
     */
    @ParameterizedTest
    @MethodSource("validArguments")
    public void shouldConvertEntityToOBObject(final MessageType messageType, final URI uri, final String entity, final String expected) throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(messageType);
        Request request = new Request();
        request.setEntity(entity);
        request.setUri(uri);
        Expression<String> expression =
                Expression.valueOf(entity,
                        String.class);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK, "", expression);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        if (messageType.equals(MessageType.REQUEST)) {
            assertThat(request.getEntity().getString()).isEqualTo(expected);
        } else if (messageType.equals(MessageType.RESPONSE)) {
            assertThat(response.getEntity().getString()).isEqualTo(expected);
        }

    }

    /**
     Case: The handle call from the filter when messageType=response is not successful<br/>
     - Expected the response from the last handle
     * <pre>
     * {@code {
     *      "name": "IntentConverterFilter-name"
     *      "type": "IntentConverterFilter",
     *      "config": {
     *         "messageType: "response"
     *      }
     *  }
     *  }
     * </pre>
     */
    @Test
    public void nextHandleNotSuccessfulWhenResponse() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.RESPONSE);
        String errorEntity = "{\"error\":\"An Error happens in the next.handle\"}";
        Expression<String> entity =
                Expression.valueOf(errorEntity,
                        String.class);
        StaticResponseHandler handler = new StaticResponseHandler(Status.BAD_REQUEST, "", entity);
        Request request = new Request();
        request.setUri(_URI_v318);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).isEqualTo(errorEntity);
    }

    /**
     Case: The payload content is empty and is expected an error
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
     */
    @Test
    public void shouldResponseWithErrorWhenEmptyEntity() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Request request = new Request();
        request.setUri(_URI_v318);
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getCause()).isExactlyInstanceOf(Exception.class)
                .hasMessageContaining("The entity to be converted should not be null");
    }

    /**
     Case: The payload content is not a json payload and is expected an error
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
     */
    @Test
    public void shouldResponseWithErrorWhenWrongEntity() throws Exception {
        // Given
        String entity = "Is not a json string";
        Request request = new Request();
        request.setEntity(entity);
        request.setUri(_URI_v318);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getCause()).isExactlyInstanceOf(JsonParseException.class)
                .hasMessageContaining("Unrecognized token 'Is': was expecting (JSON String, Number, Array, Object or token 'null', 'true' or 'false')");
    }

    @Test
    public void shouldRaiseAnErrorWhenNotFindConverter() throws Exception {
        // Given
        Request request = new Request();
        request.setEntity(accountAccessIntent);
        request.setUri(URI.create("/rs/open-banking/v3.1/aisp/account-access-consents"));
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getCause()).isExactlyInstanceOf(RuntimeException.class)
                .hasMessageContaining("Couldn't find the ACCOUNT_ACCESS_CONSENT converter for version v3_1");
    }

    @Test
    public void shouldRaiseAnErrorWhenNotIdentifyTheIntentType() throws Exception {
        // Given
        Request request = new Request();
        request.setEntity(accountRequest);
        request.setUri(_URI_v318);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getCause()).isExactlyInstanceOf(RuntimeException.class)
                .hasMessageContaining("Couldn't identify the intent type");
    }

    @Test
    public void shouldRaiseAnErrorWhenPayloadNotHaveData() throws Exception {
        // Given
        Request request = new Request();
        request.setEntity(dataError);
        request.setUri(_URI_v318);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getCause()).isExactlyInstanceOf(Exception.class)
                .hasMessageContaining("The entity doesn't have 'Data' Object to identify the intent type");
    }

    @Test
    public void shouldRaiseAnErrorWhenPayloadNotHaveConsentId() throws Exception {
        // Given
        Request request = new Request();
        request.setEntity(consentIdError);
        request.setUri(_URI_v318);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getCause()).isExactlyInstanceOf(Exception.class)
                .hasMessageContaining("The entity doesn't have 'ConsentId' to identify the intent type");
    }

    @Test
    public void shouldRaiseAnErrorWhenPayloadHaveWrongConsentId() throws Exception {
        // Given
        Request request = new Request();
        request.setEntity(intentTypeError);
        request.setUri(_URI_v318);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getCause()).isExactlyInstanceOf(Exception.class)
                .hasMessageContaining("It cannot be possible to identify the intent type with the consentId ");
    }

    /**
     Case: The heaplet is created properly with required configuration
     */
    @Test
    public void shouldCreateHeaplet() throws Exception {
        // Given
        final JsonValue config = json(
                object(
                        field("messageType", MessageType.REQUEST.toString().toLowerCase())
                ));
        EnvironmentHeap heap = mock(EnvironmentHeap.class);
        final IntentConverterFilter.Heaplet heaplet = new IntentConverterFilter.Heaplet();
        final IntentConverterFilter filter = (IntentConverterFilter) heaplet.create(Name.of("IntentConverterFilter"),
                config,
                heap);
        assertThat(filter).isNotNull();
    }

    /**
     * Raise an error creating the heaplet with wrong configuration values
     */
    @Test
    public void shouldReturnErrorWhenCreateHeapletWithWrongConfiguration() {
        // Given
        String wrongMessageType = "WRONG_MESSAGE_TYPE";
        final JsonValue config = json(
                object(
                        field("messageType", wrongMessageType)
                ));
        EnvironmentHeap heap = mock(EnvironmentHeap.class);
        final IntentConverterFilter.Heaplet heaplet = new IntentConverterFilter.Heaplet();
        assertThatThrownBy(() ->
                heaplet.create(Name.of("IntentConverterFilter"),
                        config,
                        heap)).isInstanceOf(Exception.class)
                .hasMessageContaining(String.format("Expecting String containing one of: %s", MessageType.values()));
    }
}
