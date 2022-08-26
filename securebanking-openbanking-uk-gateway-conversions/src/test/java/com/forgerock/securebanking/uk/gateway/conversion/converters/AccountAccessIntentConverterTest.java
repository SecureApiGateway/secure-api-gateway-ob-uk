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
package com.forgerock.securebanking.uk.gateway.conversion.converters;

import com.adelean.inject.resources.junit.jupiter.GivenJsonResource;
import com.adelean.inject.resources.junit.jupiter.GivenTextResource;
import com.adelean.inject.resources.junit.jupiter.TestWithResources;
import com.adelean.inject.resources.junit.jupiter.WithJacksonMapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AccountAccessIntentConverter}
 */
@TestWithResources
public class AccountAccessIntentConverterTest {

    @GivenTextResource("accountAccessIntent.json")
    String accountAccessIntent;

    @WithJacksonMapper // to specify which ObjectMapper is used to parse the JSON string
    ObjectMapper objectMapper = AccountAccessIntentConverter.genericConverterMapper();
    @GivenJsonResource("accountAccessIntent.json")
    OBReadConsentResponse1 obReadConsentResponse1Expected;

    @Test
    public void shouldConvertAccountAccessIntent() {
        assertThat(accountAccessIntent).isNotEmpty();
        AccountAccessIntentConverter converter = new AccountAccessIntentConverter();
        OBReadConsentResponse1 obReadConsentResponse1 = converter.convertFromJsonString(accountAccessIntent);
        assertThat(obReadConsentResponse1).isNotNull();
        assertThat(obReadConsentResponse1).isEqualTo(obReadConsentResponse1Expected);
    }

    @Test
    public void shouldReturnNulls() {
        AccountAccessIntentConverter converter = new AccountAccessIntentConverter();
        OBReadConsentResponse1 obReadConsentResponse1 = converter.convertFromJsonString("{\"accountAccessIntent\":\"some value\"}");
        assertThat(obReadConsentResponse1).isNotNull();
        assertThat(obReadConsentResponse1.getData()).isNull();
        assertThat(obReadConsentResponse1.getRisk()).isNull();
        assertThat(obReadConsentResponse1.getLinks()).isNull();
        assertThat(obReadConsentResponse1.getMeta()).isNull();
    }

    @Test
    public void shouldConvertListOfAccountAccessIntents() {
        assertThat(accountAccessIntent).isNotEmpty();
        AccountAccessIntentConverter converter = new AccountAccessIntentConverter();
        List<OBReadConsentResponse1> obReadConsentResponse1List = converter.createFromJsonStrings(Arrays.asList(accountAccessIntent, accountAccessIntent));
        assertThat(obReadConsentResponse1List).isNotEmpty();
        assertThat(obReadConsentResponse1List.size()).isEqualTo(2);
        assertThat(obReadConsentResponse1List.get(0)).isEqualTo(obReadConsentResponse1Expected);
        assertThat(obReadConsentResponse1List.get(1)).isEqualTo(obReadConsentResponse1Expected);
    }

    @Test
    public void shouldRaiseAnError() {
        AccountAccessIntentConverter converter = new AccountAccessIntentConverter();
        Assertions.assertThrows(
                RuntimeException.class, () ->
                        converter.convertFromJsonString("this is not a json string")
        );
    }
}
