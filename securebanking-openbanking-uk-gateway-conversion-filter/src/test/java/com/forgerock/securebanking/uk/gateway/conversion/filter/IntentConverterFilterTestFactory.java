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

import org.forgerock.openig.el.Expression;
import org.forgerock.openig.util.MessageType;

import java.util.List;

public class IntentConverterFilterTestFactory {

    protected static IntentConverterFilter getFilterInstance(final MessageType messageType){
        return getFilterInstance(messageType,null, List.of(MessageType.REQUEST));
    }

    protected static IntentConverterFilter getFilterInstance(final MessageType messageType, final Expression<String> entity){
        return new IntentConverterFilter(messageType, entity, List.of(MessageType.REQUEST));
    }

    protected static IntentConverterFilter getFilterInstance(final MessageType messageType, final List<MessageType> resultTo){
        return new IntentConverterFilter(messageType,null, resultTo);
    }

    protected static IntentConverterFilter getFilterInstance(final MessageType messageType, final Expression<String> entity, final List<MessageType> resultTo){
        return new IntentConverterFilter(
                messageType == null ? MessageType.REQUEST : messageType,
                entity,
                resultTo == null ? List.of(MessageType.REQUEST) : resultTo
        );
    }
}
