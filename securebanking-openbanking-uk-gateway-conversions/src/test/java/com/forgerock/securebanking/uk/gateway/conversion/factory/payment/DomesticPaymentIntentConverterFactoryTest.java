package com.forgerock.securebanking.uk.gateway.conversion.factory.payment;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic.DomesticPaymentIntentConverter4;
import com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic.DomesticPaymentIntentConverter5;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Unit test for {@link DomesticPaymentIntentConverterFactory}
 */
public class DomesticPaymentIntentConverterFactoryTest {

    private static Stream<Arguments> validArguments() {
        return Stream.of(
                arguments(
                        OBVersion.v3_1_4,
                        DomesticPaymentIntentConverter4.class

                ),
                arguments(
                        OBVersion.v3_1_8,
                        DomesticPaymentIntentConverter5.class

                )
        );
    }

    @ParameterizedTest
    @MethodSource("validArguments")
    public void shouldReturnDomesticPaymentIntentConverter(OBVersion obVersion, Class expectedClass) {
        assertThat(DomesticPaymentIntentConverterFactory.getConverter(obVersion).getClass())
                .isExactlyInstanceOf(expectedClass.getClass());
    }

    @Test
    public void couldNotFindTheConverter() {
        assertThatThrownBy(() ->
                DomesticPaymentIntentConverterFactory.getConverter(OBVersion.v3_1)
        ).isExactlyInstanceOf(RuntimeException.class)
                .hasMessageContaining("Couldn't find the %s converter for version %s", IntentType.PAYMENT_DOMESTIC_CONSENT.name(), OBVersion.v3_1.name());
    }
}
