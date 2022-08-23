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

import org.joda.time.DateTime;
import uk.org.openbanking.datamodel.common.OBActiveOrHistoricCurrencyAndAmount;
import uk.org.openbanking.datamodel.common.OBChargeBearerType1Code;
import uk.org.openbanking.datamodel.common.OBExternalPaymentContext1Code;
import uk.org.openbanking.datamodel.common.OBRisk1;
import uk.org.openbanking.datamodel.payment.*;

import java.util.List;
import java.util.Objects;

public class DomesticStandingOrderExpectedFactory {

    private static OBWriteDomesticStandingOrderConsentResponse5 _OBWriteDomesticStandingOrderConsentResponse5;
    private static OBWriteDomesticStandingOrderConsentResponse6 _OBWriteDomesticStandingOrderConsentResponse6;

    public static OBWriteDomesticStandingOrderConsentResponse5 getExpectedOBWriteDomesticStandingOrderConsentResponse5() {
        if (Objects.isNull(_OBWriteDomesticStandingOrderConsentResponse5)) {
            _OBWriteDomesticStandingOrderConsentResponse5 = getExpected_OBWriteDomesticStandingOrderConsentResponse5();
        }
        return _OBWriteDomesticStandingOrderConsentResponse5;
    }

    public static OBWriteDomesticStandingOrderConsentResponse6 getExpectedOBWriteDomesticStandingOrderConsentResponse6() {
        if (Objects.isNull(_OBWriteDomesticStandingOrderConsentResponse6)) {
            _OBWriteDomesticStandingOrderConsentResponse6 = getExpected_OBWriteDomesticStandingOrderConsentResponse6();
        }
        return _OBWriteDomesticStandingOrderConsentResponse6;
    }

    private static OBWriteDomesticStandingOrderConsentResponse5 getExpected_OBWriteDomesticStandingOrderConsentResponse5() {
        return new OBWriteDomesticStandingOrderConsentResponse5().data(
                        new OBWriteDomesticStandingOrderConsentResponse5Data()
                                .consentId("PDSOC_40af6f9b-61dc-40d6-94c0-635f00b69ff2")
                                .creationDateTime(DateTime.parse("2022-09-09T16:11:05.648Z"))
                                .status(OBWriteDomesticStandingOrderConsentResponse5Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-09T16:11:05.648Z"))
                                .permission(OBExternalPermissions2Code.CREATE)
                                .readRefundAccount(OBReadRefundAccountEnum.YES)
                                .cutOffDateTime(null)
                                .charges(
                                        List.of(
                                                new OBWriteDomesticConsentResponse4DataCharges()
                                                        .chargeBearer(OBChargeBearerType1Code.BORNEBYDEBTOR)
                                                        .type("UK.OBIE.CHAPSOut")
                                                        .amount(
                                                                new OBActiveOrHistoricCurrencyAndAmount()
                                                                        .amount("1.5")
                                                                        .currency("GBP")
                                                        )
                                        )
                                )
                                .initiation(
                                        new OBWriteDomesticStandingOrder3DataInitiation()
                                                .frequency("QtrDay:ENGLISH")
                                                .reference("Reference text")
                                                .numberOfPayments(null)
                                                .firstPaymentDateTime(DateTime.parse("2022-06-21T06:06:06+00:00"))
                                                .recurringPaymentDateTime(null)
                                                .finalPaymentDateTime(DateTime.parse("2023-03-20T06:06:06+00:00"))
                                                .firstPaymentAmount(
                                                        new OBWriteDomesticStandingOrder3DataInitiationFirstPaymentAmount()
                                                                .amount("165.88")
                                                                .currency("GBP")
                                                )
                                                .recurringPaymentAmount(
                                                        new OBWriteDomesticStandingOrder3DataInitiationRecurringPaymentAmount()
                                                                .amount("65")
                                                                .currency("GBP")
                                                )
                                                .finalPaymentAmount(
                                                        new OBWriteDomesticStandingOrder3DataInitiationFinalPaymentAmount()
                                                                .amount("525.83")
                                                                .currency("GBP")
                                                )
                                                .debtorAccount(null)
                                                .creditorAccount(
                                                        new OBWriteDomesticStandingOrder3DataInitiationCreditorAccount()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("08080021325698")
                                                                .name("ACME Inc")
                                                                .secondaryIdentification("0002")
                                                )
                                                .supplementaryData(null)
                                )
                                .authorisation(null)
                                .scASupportData(null)
                ).risk(
                        new OBRisk1()
                                .paymentContextCode(OBExternalPaymentContext1Code.PARTYTOPARTY)
                                .merchantCategoryCode(null)
                                .merchantCustomerIdentification(null)
                                .deliveryAddress(null)
                )
                .links(null)
                .meta(null);
    }

    private static OBWriteDomesticStandingOrderConsentResponse6 getExpected_OBWriteDomesticStandingOrderConsentResponse6() {
        return new OBWriteDomesticStandingOrderConsentResponse6().data(
                        new OBWriteDomesticStandingOrderConsentResponse6Data()
                                .consentId("PDSOC_a997a361-90a1-4d36-a4eb-b34c009379d2")
                                .creationDateTime(DateTime.parse("2022-09-09T16:10:02.808Z"))
                                .status(OBWriteDomesticStandingOrderConsentResponse6Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-09T16:10:02.808Z"))
                                .permission(OBExternalPermissions2Code.CREATE)
                                .readRefundAccount(OBReadRefundAccountEnum.YES)
                                .cutOffDateTime(null)
                                .charges(
                                        List.of(
                                                new OBWriteDomesticConsentResponse5DataCharges()
                                                        .chargeBearer(OBChargeBearerType1Code.BORNEBYDEBTOR)
                                                        .type("UK.OBIE.CHAPSOut")
                                                        .amount(
                                                                new OBActiveOrHistoricCurrencyAndAmount()
                                                                        .amount("1.5")
                                                                        .currency("GBP")
                                                        )
                                        )
                                )
                                .initiation(
                                        new OBWriteDomesticStandingOrderConsentResponse6DataInitiation()
                                                .frequency("QtrDay:ENGLISH")
                                                .reference("Reference text")
                                                .numberOfPayments(null)
                                                .firstPaymentDateTime(DateTime.parse("2022-06-21T06:06:06+00:00"))
                                                .recurringPaymentDateTime(null)
                                                .finalPaymentDateTime(DateTime.parse("2023-03-20T06:06:06+00:00"))
                                                .firstPaymentAmount(
                                                        new OBWriteDomesticStandingOrder3DataInitiationFirstPaymentAmount()
                                                                .amount("165.88")
                                                                .currency("GBP")
                                                )
                                                .recurringPaymentAmount(
                                                        new OBWriteDomesticStandingOrder3DataInitiationRecurringPaymentAmount()
                                                                .amount("65")
                                                                .currency("GBP")
                                                )
                                                .finalPaymentAmount(
                                                        new OBWriteDomesticStandingOrder3DataInitiationFinalPaymentAmount()
                                                                .amount("525.83")
                                                                .currency("GBP")
                                                )
                                                .debtorAccount(null)
                                                .creditorAccount(
                                                        new OBWriteDomesticStandingOrder3DataInitiationCreditorAccount()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("08080021325698")
                                                                .name("ACME Inc")
                                                                .secondaryIdentification("0002")
                                                )
                                                .supplementaryData(null)
                                )
                                .authorisation(null)
                                .scASupportData(null)
                                .debtor(null)
                ).risk(
                        new OBRisk1()
                                .paymentContextCode(OBExternalPaymentContext1Code.PARTYTOPARTY)
                                .merchantCategoryCode(null)
                                .merchantCustomerIdentification(null)
                                .deliveryAddress(null)
                )
                .links(null)
                .meta(null);
    }
}
