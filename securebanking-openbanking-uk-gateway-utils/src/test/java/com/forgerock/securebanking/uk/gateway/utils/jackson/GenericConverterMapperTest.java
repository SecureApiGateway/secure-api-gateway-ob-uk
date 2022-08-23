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
package com.forgerock.securebanking.uk.gateway.utils.jackson;

import com.adelean.inject.resources.junit.jupiter.GivenTextResource;
import com.adelean.inject.resources.junit.jupiter.TestWithResources;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.joda.time.DateTime;
import org.junit.jupiter.api.Test;
import uk.org.openbanking.datamodel.account.OBExternalPermissions1Code;
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1;
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1Data;
import uk.org.openbanking.datamodel.account.OBRisk2;
import uk.org.openbanking.datamodel.common.OBExternalRequestStatus1Code;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link GenericConverterMapper}
 */
@TestWithResources
public class GenericConverterMapperTest {

    @GivenTextResource("accountAccessIntent.json")
    String accountAccessIntent;

    @Test
    public void shouldMapResource() throws JsonProcessingException {
        OBReadConsentResponse1 obReadConsentResponse1 = GenericConverterMapper.getMapper().readValue(accountAccessIntent, OBReadConsentResponse1.class);
        assertThat(obReadConsentResponse1).isEqualTo(getExpected());
    }

    private OBReadConsentResponse1 getExpected() {
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
