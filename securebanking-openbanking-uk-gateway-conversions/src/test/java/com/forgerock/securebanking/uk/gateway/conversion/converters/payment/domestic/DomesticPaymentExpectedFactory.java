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
import uk.org.openbanking.datamodel.common.*;
import uk.org.openbanking.datamodel.payment.*;

import java.util.List;
import java.util.Objects;

public class DomesticPaymentExpectedFactory {

    private static OBWriteDomesticConsentResponse4 _OBWriteDomesticConsentResponse4;
    private static OBWriteDomesticConsentResponse5 _OBWriteDomesticConsentResponse5;

    public static OBWriteDomesticConsentResponse4 getExpectedOBWriteDomesticConsentResponse4() {
        if (Objects.isNull(_OBWriteDomesticConsentResponse4)) {
            _OBWriteDomesticConsentResponse4 = getExpected_OBWriteDomesticConsentResponse4();
        }
        return _OBWriteDomesticConsentResponse4;
    }

    public static OBWriteDomesticConsentResponse5 getExpectedOBWriteDomesticConsentResponse5() {
        if (Objects.isNull(_OBWriteDomesticConsentResponse5)) {
            _OBWriteDomesticConsentResponse5 = getExpected_OBWriteDomesticConsentResponse5();
        }
        return _OBWriteDomesticConsentResponse5;
    }

    private static OBWriteDomesticConsentResponse4 getExpected_OBWriteDomesticConsentResponse4() {
        return new OBWriteDomesticConsentResponse4().data(
                        new OBWriteDomesticConsentResponse4Data()
                                .consentId("PDC_2844f314-cce8-4607-8594-939e3a6bd2e1")
                                .creationDateTime(DateTime.parse("2022-09-09T13:51:17.246Z"))
                                .status(OBWriteDomesticConsentResponse4Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-09T13:51:17.246Z"))
                                .readRefundAccount(OBReadRefundAccountEnum.YES)
                                .cutOffDateTime(null)
                                .expectedExecutionDateTime(null)
                                .expectedSettlementDateTime(null)
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
                                        new OBWriteDomestic2DataInitiation()
                                                .instructionIdentification("ACME412")
                                                .endToEndIdentification("FRESCO.21302.GFX.20")
                                                .localInstrument(null)
                                                .instructedAmount(
                                                        new OBWriteDomestic2DataInitiationInstructedAmount()
                                                                .amount("165.88")
                                                                .currency("GBP")
                                                )
                                                .debtorAccount(null)
                                                .creditorAccount(
                                                        new OBWriteDomestic2DataInitiationCreditorAccount()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("08080021325698")
                                                                .name("ACME Inc")
                                                                .secondaryIdentification("0002")
                                                )
                                                .creditorPostalAddress(null)
                                                .remittanceInformation(
                                                        new OBWriteDomestic2DataInitiationRemittanceInformation()
                                                                .unstructured("Internal ops code 5120101")
                                                                .reference("FRESCO-101")
                                                )
                                                .supplementaryData(null)
                                )
                                .authorisation(null)
                                .scASupportData(null)
                ).risk(
                        new OBRisk1()
                                .paymentContextCode(OBExternalPaymentContext1Code.ECOMMERCEGOODS)
                                .merchantCategoryCode("5967")
                                .merchantCustomerIdentification("053598653254")
                                .deliveryAddress(
                                        new OBRisk1DeliveryAddress()
                                                .addAddressLineItem("Flat 7")
                                                .addAddressLineItem("Acacia Lodge")
                                                .streetName("Acacia Avenue")
                                                .buildingNumber("27")
                                                .postCode("GU31 2ZZ")
                                                .townName("Sparsholt")
                                                .countrySubDivision(null)
                                                .country("UK")
                                )
                )
                .links(null)
                .meta(null);
    }

    private static OBWriteDomesticConsentResponse5 getExpected_OBWriteDomesticConsentResponse5() {
        return new OBWriteDomesticConsentResponse5().data(
                        new OBWriteDomesticConsentResponse5Data()
                                .consentId("PDC_99833f3a-bab5-4f2e-98bc-af64698570ba")
                                .creationDateTime(DateTime.parse("2022-09-09T12:50:59.793Z"))
                                .status(OBWriteDomesticConsentResponse5Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-09T12:50:59.793Z"))
                                .readRefundAccount(OBReadRefundAccountEnum.YES)
                                .cutOffDateTime(null)
                                .expectedExecutionDateTime(null)
                                .expectedSettlementDateTime(null)
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
                                        new OBWriteDomestic2DataInitiation()
                                                .instructionIdentification("ACME412")
                                                .endToEndIdentification("FRESCO.21302.GFX.20")
                                                .localInstrument(null)
                                                .instructedAmount(
                                                        new OBWriteDomestic2DataInitiationInstructedAmount()
                                                                .amount("165.88")
                                                                .currency("GBP")
                                                )
                                                .debtorAccount(null)
                                                .creditorAccount(
                                                        new OBWriteDomestic2DataInitiationCreditorAccount()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("08080021325698")
                                                                .name("ACME Inc")
                                                                .secondaryIdentification("0002")
                                                )
                                                .creditorPostalAddress(null)
                                                .remittanceInformation(
                                                        new OBWriteDomestic2DataInitiationRemittanceInformation()
                                                                .unstructured("Internal ops code 5120101")
                                                                .reference("FRESCO-101")
                                                )
                                                .supplementaryData(null)
                                )
                                .authorisation(null)
                                .scASupportData(null)
                                .debtor(null)
                ).risk(
                        new OBRisk1()
                                .paymentContextCode(OBExternalPaymentContext1Code.ECOMMERCEGOODS)
                                .merchantCategoryCode("5967")
                                .merchantCustomerIdentification("053598653254")
                                .deliveryAddress(
                                        new OBRisk1DeliveryAddress()
                                                .addAddressLineItem("Flat 7")
                                                .addAddressLineItem("Acacia Lodge")
                                                .streetName("Acacia Avenue")
                                                .buildingNumber("27")
                                                .postCode("GU31 2ZZ")
                                                .townName("Sparsholt")
                                                .countrySubDivision(null)
                                                .country("UK")
                                )
                )
                .links(null)
                .meta(null);
    }
}
