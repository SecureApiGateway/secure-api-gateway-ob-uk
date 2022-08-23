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
package com.forgerock.securebanking.uk.gateway.conversion.factory.payment;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international.InternationalScheduledPaymentIntentConverter5;
import com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international.InternationalScheduledPaymentIntentConverter6;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Unit test for {@link InternationalScheduledPaymentIntentConverterFactory}
 */
public class InternationalScheduledPaymentIntentConverterFactoryTest {

    private static Stream<Arguments> validArguments() {
        return Stream.of(
                arguments(
                        OBVersion.v3_1_4,
                        InternationalScheduledPaymentIntentConverter5.class

                ),
                arguments(
                        OBVersion.v3_1_8,
                        InternationalScheduledPaymentIntentConverter6.class

                )
        );
    }

    @ParameterizedTest
    @MethodSource("validArguments")
    public void shouldReturnDomesticStandingOrderIntentConverter(OBVersion obVersion, Class expectedClass) {
        assertThat(InternationalScheduledPaymentIntentConverterFactory.getConverter(obVersion).getClass())
                .isExactlyInstanceOf(expectedClass.getClass());
    }

    @Test
    public void couldNotFindTheConverter() {
        assertThatThrownBy(() ->
                InternationalScheduledPaymentIntentConverterFactory.getConverter(OBVersion.v3_1)
        ).isExactlyInstanceOf(RuntimeException.class)
                .hasMessageContaining("Couldn't find the %s converter for version %s", IntentType.PAYMENT_INTERNATIONAL_SCHEDULED_CONSENT.name(), OBVersion.v3_1.name());
    }
}
