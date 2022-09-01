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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
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

import java.util.List;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.forgerock.json.JsonValue.*;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link IntentConverterFilter}
 */
@TestWithResources
public class IntentConverterFilterTest {

    @GivenTextResource("accountAccessIntent.json")
    String accountAccessIntent;

    @Test
    public void shouldConvertIntentToOBObjectFromRequest() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(IntentType.ACCOUNT_ACCESS_CONSENT, MessageType.REQUEST);
        Request request = new Request();
        request.setEntity(accountAccessIntent);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getString()).isEqualTo(getExpectedResponse());
    }

    @Test
    public void shouldConvertIntentToOBObjectFromRequestToRequest() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(
                IntentType.ACCOUNT_ACCESS_CONSENT,
                MessageType.REQUEST,
                List.of(MessageType.REQUEST)
        );
        Request request = new Request();
        request.setEntity(accountAccessIntent);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(request.getEntity().getString()).isEqualTo(getExpectedResponse());
    }

    @Test
    public void shouldConvertIntentToOBObjectFromRequestToBoth() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(
                IntentType.ACCOUNT_ACCESS_CONSENT,
                MessageType.REQUEST,
                List.of(MessageType.REQUEST, MessageType.RESPONSE)
        );
        Request request = new Request();
        request.setEntity(accountAccessIntent);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(request.getEntity().getString()).isEqualTo(getExpectedResponse());
        assertThat(response.getEntity().getString()).isEqualTo(getExpectedResponse());
    }

    @Test
    public void shouldConvertIntentToOBObjectFromResponseToBoth() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(
                IntentType.ACCOUNT_ACCESS_CONSENT,
                MessageType.RESPONSE,
                List.of(MessageType.REQUEST, MessageType.RESPONSE)
        );
        Expression<String> expression =
                Expression.valueOf(accountAccessIntent,
                        String.class);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK, "", expression);
        Request request = new Request();
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(request.getEntity().getString()).isEqualTo(getExpectedResponse());
        assertThat(response.getEntity().getString()).isEqualTo(getExpectedResponse());
    }

    @Test
    public void shouldConvertIntentToOBObjectFromResponse() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(IntentType.ACCOUNT_ACCESS_CONSENT, MessageType.RESPONSE);
        Expression<String> expression =
                Expression.valueOf(accountAccessIntent,
                        String.class);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK, "", expression);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), new Request()).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getString()).isEqualTo(getExpectedResponse());
    }

    @Test
    public void shouldResponseWithErrorWhenWrongRequestEntity() throws Exception {
        // Given
        String entity = "Is not a json string";
        IntentConverterFilter filter = new IntentConverterFilter(IntentType.ACCOUNT_ACCESS_CONSENT, MessageType.REQUEST);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), new Request()).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
    }

    @Test
    public void shouldResponseWithErrorWhenWrongResponseEntity() throws Exception {
        // Given
        String entity = "Is not a json string";
        IntentConverterFilter filter = new IntentConverterFilter(IntentType.ACCOUNT_ACCESS_CONSENT, MessageType.RESPONSE);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        handler.handle(new RootContext(), new Request()).getOrThrow().setEntity(entity);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), new Request()).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
    }

    @Test
    public void shouldCreateHeaplet() throws Exception {
        // Given
        final JsonValue config = json(
                object(
                        field("intentType", IntentType.ACCOUNT_ACCESS_CONSENT.toString()),
                        field("payloadFrom", MessageType.REQUEST.toString())
                ));
        EnvironmentHeap heap = mock(EnvironmentHeap.class);
        final IntentConverterFilter.Heaplet heaplet = new IntentConverterFilter.Heaplet();
        final IntentConverterFilter filter = (IntentConverterFilter) heaplet.create(Name.of("IntentConverterFilter"),
                config,
                heap);
        assertThat(filter).isNotNull();
    }

    @Test
    public void shouldCreateHeapletWithOptionals() throws Exception {
        // Given
        final JsonValue config = json(
                object(
                        field("intentType", IntentType.ACCOUNT_ACCESS_CONSENT.toString()),
                        field("payloadFrom", MessageType.REQUEST.toString()),
                        field("resultTo", List.of(MessageType.REQUEST.toString(), MessageType.RESPONSE.toString()))
                ));
        EnvironmentHeap heap = mock(EnvironmentHeap.class);
        final IntentConverterFilter.Heaplet heaplet = new IntentConverterFilter.Heaplet();
        final IntentConverterFilter filter = (IntentConverterFilter) heaplet.create(Name.of("IntentConverterFilter"),
                config,
                heap);
        assertThat(filter).isNotNull();
    }

    @Test
    public void shouldReturnErrorWhenCreateHeapletWithWrongOptionals() throws Exception {
        // Given
        final JsonValue config = json(
                object(
                        field("intentType", IntentType.ACCOUNT_ACCESS_CONSENT.toString()),
                        field("payloadFrom", MessageType.REQUEST.toString()),
                        field("resultTo", List.of(MessageType.REQUEST.toString(), "WRONG_MESSAGE_TYPE"))
                ));
        EnvironmentHeap heap = mock(EnvironmentHeap.class);
        final IntentConverterFilter.Heaplet heaplet = new IntentConverterFilter.Heaplet();
        assertThatThrownBy(() ->
                heaplet.create(Name.of("IntentConverterFilter"),
                config,
                heap)).isInstanceOf(JsonValueException.class)
                .hasMessageContaining("Configuration 'resultTo' [REQUEST, WRONG_MESSAGE_TYPE] list contains not supported values," +
                        " all configuration values should be a MessageType values.");
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
