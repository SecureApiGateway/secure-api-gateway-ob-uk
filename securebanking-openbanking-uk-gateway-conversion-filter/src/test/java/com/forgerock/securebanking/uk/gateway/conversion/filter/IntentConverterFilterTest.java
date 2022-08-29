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
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.handler.StaticResponseHandler;
import org.forgerock.openig.heap.EnvironmentHeap;
import org.forgerock.openig.heap.Name;
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
    public void shouldConvertIntentToOBObject() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(IntentType.ACCOUNT_ACCESS_CONSENT, null);
        Request request = new Request();
        request.setEntity(accountAccessIntent);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getJson()).isEqualTo(getExpectedResponse());
    }

    @Test
    public void shouldConvertIntentToOBObjectWhenIntentContent() throws Exception {
        // Given
        IntentConverterFilter filter = new IntentConverterFilter(IntentType.ACCOUNT_ACCESS_CONSENT, accountAccessIntent);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), new Request()).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getJson()).isEqualTo(getExpectedResponse());
    }

    @Test
    public void shouldResponseWithErrorWhenIntentContent() throws Exception {
        // Given
        String entity = "Is not a json string";
        IntentConverterFilter filter = new IntentConverterFilter(IntentType.ACCOUNT_ACCESS_CONSENT, entity);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), new Request()).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getCause().getMessage()).contains(entity);
    }

    @Test
    public void shouldResponseWithError() throws Exception {
        // Given
        String entity = "Is not a json string";
        IntentConverterFilter filter = new IntentConverterFilter(IntentType.ACCOUNT_ACCESS_CONSENT, null);
        Request request = new Request();
        request.setEntity(entity);
        StaticResponseHandler handler = new StaticResponseHandler(Status.OK);
        // When
        Handler chain = Handlers.chainOf(handler, singletonList(filter));
        Response response = chain.handle(new RootContext(), request).get();
        // then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getCause().getMessage()).contains(entity);
    }

    @Test
    public void shouldCreateHeaplet() throws Exception {
        // Given
        final JsonValue config = json(object(field("intentType", IntentType.ACCOUNT_ACCESS_CONSENT.toString())));
        EnvironmentHeap heap = mock(EnvironmentHeap.class);
        final IntentConverterFilter.Heaplet heaplet = new IntentConverterFilter.Heaplet();
        final IntentConverterFilter filter = (IntentConverterFilter) heaplet.create(Name.of("IntentIDMToOBObjectFilter"),
                config,
                heap);
        assertThat(filter).isNotNull();
    }

    private static OBReadConsentResponse1 getExpectedResponse() {
        return new OBReadConsentResponse1().data(
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

        ).risk(new OBRisk2());
    }
}
