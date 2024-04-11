/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.fapi;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;
import java.util.UUID;

import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RequestAuditContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.services.context.TransactionIdContext;
import org.junit.jupiter.api.Test;

class FAPIUtilsTest {
    @Test
    void getFapiInteractionIdForDisplay() {
        // Verify we get a human-readable display when no x-fapi-interaction-id can be found
        assertEquals("No x-fapi-interaction-id", FAPIUtils.getFapiInteractionIdForDisplay(null));
        assertEquals("No x-fapi-interaction-id", FAPIUtils.getFapiInteractionIdForDisplay(new AttributesContext(null)));

        final TransactionIdContext transactionIdContext = new TransactionIdContext(null, new TransactionId("1234-5678-9123-4567"));
        assertEquals("1234-5678-9123-4567", FAPIUtils.getFapiInteractionIdForDisplay(transactionIdContext));
        assertEquals("1234-5678-9123-4567", FAPIUtils.getFapiInteractionIdForDisplay(new AttributesContext(transactionIdContext)));
        assertEquals("1234-5678-9123-4567", FAPIUtils.getFapiInteractionIdForDisplay(new RequestAuditContext(new AttributesContext(transactionIdContext))));
    }

    @Test
    void getFapiInteractionId() {
        final AttributesContext wrongInteractionIdAttrType = new AttributesContext(new RootContext());
        wrongInteractionIdAttrType.getAttributes().put(FAPIUtils.X_FAPI_INTERACTION_ID, 123);

        Context[] contextsWithoutInteractionId = new Context[]{
                new RootContext(),
                new AttributesContext(new RootContext()),
                wrongInteractionIdAttrType,
                new TransactionIdContext(new RootContext(), new TransactionId())
        };
        for (final Context invalidContext : contextsWithoutInteractionId) {
            assertEquals(Optional.empty(), FAPIUtils.getFapiInteractionId(invalidContext));
        }

        final AttributesContext validAttributesContext = new AttributesContext(new RootContext());
        final String fapiInteractionId = UUID.randomUUID().toString();
        validAttributesContext.getAttributes().put(FAPIUtils.X_FAPI_INTERACTION_ID, fapiInteractionId);

        assertEquals(fapiInteractionId, FAPIUtils.getFapiInteractionId(validAttributesContext).get());
        assertEquals(fapiInteractionId, FAPIUtils.getFapiInteractionId(new TransactionIdContext(validAttributesContext, new TransactionId())).get());

    }
}