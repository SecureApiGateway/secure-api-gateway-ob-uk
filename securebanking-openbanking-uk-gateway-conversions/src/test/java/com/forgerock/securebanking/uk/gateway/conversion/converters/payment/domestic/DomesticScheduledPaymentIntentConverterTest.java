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
package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic;

import com.adelean.inject.resources.junit.jupiter.GivenTextResource;
import com.adelean.inject.resources.junit.jupiter.TestWithResources;
import com.forgerock.securebanking.uk.gateway.conversion.converters.GenericIntentConverter;
import com.forgerock.securebanking.uk.gateway.conversion.jackson.GenericConverterMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticScheduledConsentResponse4;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticScheduledConsentResponse5;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Unit tests for <br/>
 * {@link DomesticScheduledPaymentIntentConverter4}
 * {@link DomesticScheduledPaymentIntentConverter5}
 */
@TestWithResources
public class DomesticScheduledPaymentIntentConverterTest {

    @GivenTextResource("domesticScheduledPaymentIntent4.json")
    static String domesticScheduledPaymentIntent4;

    @GivenTextResource("domesticScheduledPaymentIntent5.json")
    static String domesticScheduledPaymentIntent5;

    private static Stream<Arguments> validArguments() {
        return Stream.of(
                arguments(
                        new DomesticScheduledPaymentIntentConverter4(),
                        OBWriteDomesticScheduledConsentResponse4.class,
                        domesticScheduledPaymentIntent4,
                        DomesticScheduledPaymentExpectedResponses.getExpectedOBWriteDomesticScheduledConsentResponse4()

                ),
                arguments(
                        new DomesticScheduledPaymentIntentConverter5(),
                        OBWriteDomesticScheduledConsentResponse5.class,
                        domesticScheduledPaymentIntent5,
                        DomesticScheduledPaymentExpectedResponses.getExpectedOBWriteDomesticScheduledConsentResponse5()

                )
        );
    }

    @ParameterizedTest
    @MethodSource("validArguments")
    public void shouldConvertDomesticScheduledPaymentIntent(GenericIntentConverter converter, Class expectedClass, String intentPayload, Object expectedResponse) {
        assertThat(intentPayload).isNotEmpty();
        Object object = converter.convertFromJsonString(intentPayload);
        assertThat(object.getClass()).isExactlyInstanceOf(expectedClass.getClass());
        assertThat(object).isNotNull();
        assertThat(object).isEqualTo(expectedResponse);
    }

    @ParameterizedTest
    @MethodSource("validArguments")
    public void shouldReturnEmptyObject(GenericIntentConverter converter, Class expectedClass) {
        Object object = converter.convertFromJsonString("{\"someField\":\"some value\"}");
        assertThat(object.getClass()).isExactlyInstanceOf(expectedClass.getClass());
        Map<String, Object> map = GenericConverterMapper.getMapper().convertValue(object, HashMap.class);
        assertThat(map.size()).isEqualTo(0);
    }

    @ParameterizedTest
    @MethodSource("validArguments")
    public void shouldConvertListOfDomesticScheduledPaymentIntents(GenericIntentConverter converter, Class expectedClass, String intentPayload, Object expectedResponse) {
        assertThat(intentPayload).isNotEmpty();
        List<Object> objects = converter.createFromJsonStrings(Arrays.asList(intentPayload, intentPayload));
        assertThat(objects).isNotEmpty();
        assertThat(objects.size()).isEqualTo(2);
        assertThat(objects.get(0).getClass()).isExactlyInstanceOf(expectedClass.getClass());
        assertThat(objects.get(0)).isEqualTo(expectedResponse);
        assertThat(objects.get(1).getClass()).isExactlyInstanceOf(expectedClass.getClass());
        assertThat(objects.get(1)).isEqualTo(expectedResponse);
    }

    @ParameterizedTest
    @MethodSource("validArguments")
    public void shouldRaiseAnError(GenericIntentConverter converter) {
        Assertions.assertThrows(
                RuntimeException.class, () ->
                        converter.convertFromJsonString("this is not a json string")
        );
    }
}
