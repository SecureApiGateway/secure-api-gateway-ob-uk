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
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.el.Expression;
import org.forgerock.openig.handler.StaticResponseHandler;
import org.forgerock.openig.heap.EnvironmentHeap;
import org.forgerock.openig.heap.Name;
import org.forgerock.openig.util.MessageType;
import org.forgerock.services.context.RootContext;
import org.joda.time.DateTime;
import org.junit.jupiter.api.Test;
import uk.org.openbanking.datamodel.account.OBExternalPermissions1Code;
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1;
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1Data;
import uk.org.openbanking.datamodel.account.OBRisk2;
import uk.org.openbanking.datamodel.common.OBExternalRequestStatus1Code;

import java.net.URI;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.forgerock.json.JsonValue.*;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link IntentConverterFilter}<br/>
 * By default the result will be in the request to be passed the next handler
 */
@TestWithResources
public class IntentConverterFilterTest {

    private static final URI _URI = URI.create("/rs/open-banking/v3.1.8/aisp/account-access-consents");

    @GivenTextResource("accountAccessIntent.json")
    String accountAccessIntent;

    @GivenTextResource("accountRequest.json") // to tests the intent type error
    String accountRequest;

    @GivenTextResource("data-error.json") // to tests the intent type error
    String dataError;

    @GivenTextResource("consentId-error.json") // to tests the intent type error
    String consentIdError;

    @GivenTextResource("intent-type-error.json") // to tests the intent type error
    String intentTypeError;

    /**
     Case: The optional entity is set in the configuration and the payload content is get from a request expression
     * <pre>
     * {@code {
     *      "name": "IntentConverterFilter-name"
     *      "type": "IntentConverterFilter",
     *      "config": {
     *         "messageType: "request",
     *         "entity": "#{request.entity.string}"
     *      }
     *  }
     *  }
     * </pre>
     */
    @Test
    public void shouldOptionalEntityRequestExpressionToOBObject() throws Exception {
        // Given
        Expression<String> expression =
                Expression.valueOf("#{request.entity.string}",
                        String.class);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST, expression);
        Request request = new Request();
        request.setEntity(accountAccessIntent);
        request.setUri(_URI);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(request.getEntity().getString()).isEqualTo(getExpectedResponse());
    }

    /**
     Case: The optional entity is set in the configuration and the payload content is get from a response expression
     * <pre>
     * {@code {
     *      "name": "IntentConverterFilter-name"
     *      "type": "IntentConverterFilter",
     *      "config": {
     *         "messageType: "response",
     *         "entity": "#{response.entity.string}"
     *      }
     *  }
     *  }
     * </pre>
     */
    @Test
    public void shouldConvertOptionalEntityResponseExpressionToOBObject() throws Exception {
        // Given
        Expression<String> expression =
                Expression.valueOf("#{response.entity.string}",
                        String.class);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.RESPONSE, expression);

        Expression<String> entity =
                Expression.valueOf(accountAccessIntent,
                        String.class);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK, "", entity);
        Request request = new Request();
        request.setUri(_URI);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));

        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(request.getEntity().getString()).isEqualTo(getExpectedResponse());
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
    @Test
    public void shouldConvertEntityFromRequestToOBObject() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST);
        Request request = new Request();
        request.setEntity(accountAccessIntent);
        request.setUri(_URI);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(request.getEntity().getString()).isEqualTo(getExpectedResponse());
    }

    /**
     Case: The payload content is get from response
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
    public void shouldConvertEntityFromResponseToOBObject() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.RESPONSE);
        Expression<String> entity =
                Expression.valueOf(accountAccessIntent,
                        String.class);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK, "", entity);
        Request request = new Request();
        request.setUri(_URI);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(request.getEntity().getString()).isEqualTo(getExpectedResponse());
    }

    /**
     Case: The payload content is get from request and the result will be set on response
     * <pre>
     * {@code {
     *      "name": "IntentConverterFilter-name"
     *      "type": "IntentConverterFilter",
     *      "config": {
     *         "messageType: "request",
     *         "resultTo": ["request"]
     *      }
     *  }
     *  }
     * </pre>
     */
    @Test
    public void shouldConvertEntityToOBObjectConvertedToResponse() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(
                MessageType.REQUEST,
                List.of(MessageType.RESPONSE)
        );
        Request request = new Request();
        request.setEntity(accountAccessIntent);
        request.setUri(_URI);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getString()).isEqualTo(getExpectedResponse());
    }

    /**
     Case: The payload content is get from request and the result will be set on request and response
     * <pre>
     * {@code {
     *      "name": "IntentConverterFilter-name"
     *      "type": "IntentConverterFilter",
     *      "config": {
     *         "messageType: "request",
     *         "resultTo": ["request", "response"]
     *      }
     *  }
     *  }
     * </pre>
     */
    @Test
    public void shouldConvertEntityToOBObjectToRequestAndResponse() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(
                MessageType.REQUEST,
                List.of(MessageType.REQUEST, MessageType.RESPONSE)
        );
        Request request = new Request();
        request.setEntity(accountAccessIntent);
        request.setUri(_URI);
        Expression<String> expression =
                Expression.valueOf(accountAccessIntent,
                        String.class);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK, "", expression);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));

        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(request.getEntity().getString()).isEqualTo(getExpectedResponse());
        assertThat(response.getEntity().getString()).isEqualTo(getExpectedResponse());
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
        Response response = chain.handle(new RootContext(), new Request()).get();
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
     *         "messageType: "request",
     *         "resultTo": ["request"]
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
        request.setUri(_URI);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST, null, null);
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
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST, null, null);
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
        request.setUri(_URI);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST, null, null);
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
        request.setUri(_URI);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST, null, null);
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
        request.setUri(_URI);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST, null, null);
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
        request.setUri(_URI);
        IntentConverterFilter filter = new IntentConverterFilter(MessageType.REQUEST, null, null);
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
     * The heaplet is created properly with optional configuration
     * @throws Exception
     */
    @Test
    public void shouldCreateHeapletWithOptionals() throws Exception {
        // Given
        final JsonValue config = json(
                object(
                        field("messageType", MessageType.REQUEST.toString().toLowerCase()),
                        field("entity", accountAccessIntent),
                        field("resultTo", List.of(MessageType.REQUEST.toString().toLowerCase(), MessageType.RESPONSE.toString()))
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
    public void shouldReturnErrorWhenCreateHeapletWithWrongOptionals() {
        // Given
        String wrongMessageType = "WRONG_MESSAGE_TYPE";
        final JsonValue config = json(
                object(
                        field("messageType", MessageType.REQUEST.toString()),
                        field("resultTo", List.of(MessageType.REQUEST.toString(), wrongMessageType))
                ));
        EnvironmentHeap heap = mock(EnvironmentHeap.class);
        final IntentConverterFilter.Heaplet heaplet = new IntentConverterFilter.Heaplet();
        assertThatThrownBy(() ->
                heaplet.create(Name.of("IntentConverterFilter"),
                        config,
                        heap)).isInstanceOf(JsonValueException.class)
                .hasMessageContaining(String.format("Configuration field 'resultTo' contains not supported value '%s'," +
                        " all configuration values should be a MessageType values.", wrongMessageType));
    }

    private static String getExpectedResponse() throws JsonProcessingException {
        return GenericConverterMapper.getMapper().writeValueAsString(
                new OBReadConsentResponse1().data(
                        new OBReadConsentResponse1Data()
                                .consentId("AAC_f5a3913a-0299-4169-8f53-0c14e6e90890")
                                .expirationDateTime(DateTime.parse("2019-08-01T00:00:00.000Z"))
                                .transactionFromDateTime(DateTime.parse("2019-04-03T00:00:00.000Z"))
                                .transactionToDateTime(DateTime.parse("2019-08-01T00:00:00.000Z"))
                                .status(OBExternalRequestStatus1Code.AWAITINGAUTHORISATION)
                                .creationDateTime(DateTime.parse("2022-08-24T11:56:29.533Z"))
                                .statusUpdateDateTime(DateTime.parse("2022-08-24T11:56:29.533Z"))
                                .permissions(
                                        List.of(
                                                OBExternalPermissions1Code.READACCOUNTSDETAIL,
                                                OBExternalPermissions1Code.READBALANCES
                                        )
                                )

                ).risk(new OBRisk2())
        );
    }
}
