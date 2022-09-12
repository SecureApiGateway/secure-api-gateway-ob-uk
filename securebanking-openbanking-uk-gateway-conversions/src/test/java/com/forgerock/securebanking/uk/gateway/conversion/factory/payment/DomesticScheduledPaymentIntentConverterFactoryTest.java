package com.forgerock.securebanking.uk.gateway.conversion.factory.payment;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic.DomesticScheduledPaymentIntentConverter4;
import com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic.DomesticScheduledPaymentIntentConverter5;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Unit test for {@link DomesticScheduledPaymentIntentConverterFactory}
 */
public class DomesticScheduledPaymentIntentConverterFactoryTest {

    private static Stream<Arguments> validArguments() {
        return Stream.of(
                arguments(
                        OBVersion.v3_1_4,
                        DomesticScheduledPaymentIntentConverter4.class

                ),
                arguments(
                        OBVersion.v3_1_8,
                        DomesticScheduledPaymentIntentConverter5.class

                )
        );
    }

    @ParameterizedTest
    @MethodSource("validArguments")
    public void shouldReturnDomesticScheduledPaymentIntentConverter(OBVersion obVersion, Class expectedClass) {
        assertThat(DomesticScheduledPaymentIntentConverterFactory.getConverter(obVersion).getClass())
                .isExactlyInstanceOf(expectedClass.getClass());
    }

    @Test
    public void couldNotFindTheConverter() {
        assertThatThrownBy(() ->
                DomesticScheduledPaymentIntentConverterFactory.getConverter(OBVersion.v3_1)
        ).isExactlyInstanceOf(RuntimeException.class)
                .hasMessageContaining("Couldn't find the %s converter for version %s", IntentType.PAYMENT_DOMESTIC_SCHEDULED_CONSENT.name(), OBVersion.v3_1.name());
    }
}
