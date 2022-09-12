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
