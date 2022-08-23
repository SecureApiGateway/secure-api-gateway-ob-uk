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
package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.international;

import org.joda.time.DateTime;
import uk.org.openbanking.datamodel.common.*;
import uk.org.openbanking.datamodel.payment.*;

import java.math.BigDecimal;
import java.util.List;
import java.util.Objects;

public class InternationalPaymentIntentExpectedFactory {
    private static OBWriteInternationalConsentResponse5 _OBWriteInternationalConsentResponse5;
    private static OBWriteInternationalConsentResponse6 _OBWriteInternationalConsentResponse6;

    public static OBWriteInternationalConsentResponse5 getExpectedOBWriteInternationalConsentResponse5() {
        if (Objects.isNull(_OBWriteInternationalConsentResponse5)) {
            _OBWriteInternationalConsentResponse5 = getExpected_OBWriteInternationalConsentResponse5();
        }
        return _OBWriteInternationalConsentResponse5;
    }

    public static OBWriteInternationalConsentResponse6 getExpectedOBWriteInternationalConsentResponse6() {
        if (Objects.isNull(_OBWriteInternationalConsentResponse6)) {
            _OBWriteInternationalConsentResponse6 = getExpected_OBWriteInternationalConsentResponse6();
        }
        return _OBWriteInternationalConsentResponse6;
    }

    private static OBWriteInternationalConsentResponse5 getExpected_OBWriteInternationalConsentResponse5() {
        return new OBWriteInternationalConsentResponse5().data(
                        new OBWriteInternationalConsentResponse5Data()
                                .consentId("PIC_2a207f20-be4f-4678-bfb1-dffe9aec8c8b")
                                .creationDateTime(DateTime.parse("2022-09-12T06:32:35.630Z"))
                                .status(OBWriteInternationalConsentResponse5Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-12T06:32:35.630Z"))
                                .readRefundAccount(OBReadRefundAccountEnum.NO)
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
                                .exchangeRateInformation(
                                        new OBWriteInternationalConsentResponse5DataExchangeRateInformation()
                                                .unitCurrency("EUR")
                                                .exchangeRate(BigDecimal.valueOf(10))
                                                .rateType(OBExchangeRateType2Code.AGREED)
                                                .contractIdentification("/tbill/2018/T102993")
                                                .expirationDateTime(null)
                                )
                                .initiation(
                                        new OBWriteInternational3DataInitiation()
                                                .instructionIdentification("ANSM020")
                                                .endToEndIdentification("FRESCO.21302.GFX.01")
                                                .localInstrument("UK.OBIE.BACS")
                                                .instructionPriority(OBPriority2Code.NORMAL)
                                                .purpose("CDCD")
                                                .extendedPurpose("Extended purpose")
                                                .chargeBearer(OBChargeBearerType1Code.SHARED)
                                                .currencyOfTransfer("EUR")
                                                .destinationCountryCode("GB")
                                                .instructedAmount(
                                                        new OBWriteDomestic2DataInitiationInstructedAmount()
                                                                .amount("10.01")
                                                                .currency("GBP")
                                                )
                                                .exchangeRateInformation(
                                                        new OBWriteInternational3DataInitiationExchangeRateInformation()
                                                                .unitCurrency("EUR")
                                                                .exchangeRate(BigDecimal.valueOf(10))
                                                                .rateType(OBExchangeRateType2Code.AGREED)
                                                                .contractIdentification("/tbill/2018/T102993")
                                                )
                                                .debtorAccount(
                                                        new OBWriteDomestic2DataInitiationDebtorAccount()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("11280001234567")
                                                                .name("Mr Shaun Ryder")
                                                                .secondaryIdentification("22")
                                                )
                                                .creditor(
                                                        new OBWriteInternational3DataInitiationCreditor()
                                                                .name("Creditor Name")
                                                                .postalAddress(
                                                                        new OBPostalAddress6()
                                                                                .addressType(OBAddressTypeCode.RESIDENTIAL)
                                                                                .department(null)
                                                                                .subDepartment(null)
                                                                                .streetName("The Mall")
                                                                                .buildingNumber("1")
                                                                                .postCode("WC1 1AB")
                                                                                .townName("London")
                                                                                .countrySubDivision(null)
                                                                                .country("UK")
                                                                                .addressLine(null)
                                                                )
                                                )
                                                .creditorAgent(
                                                        new OBWriteInternational3DataInitiationCreditorAgent()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("40400411270111")
                                                                .name("Creditor Agent Name")
                                                                .postalAddress(
                                                                        new OBPostalAddress6()
                                                                                .addressType(OBAddressTypeCode.RESIDENTIAL)
                                                                                .department(null)
                                                                                .subDepartment(null)
                                                                                .streetName("The Mall")
                                                                                .buildingNumber("1")
                                                                                .postCode("WC1 1AB")
                                                                                .townName("London")
                                                                                .countrySubDivision(null)
                                                                                .country("UK")
                                                                                .addressLine(null)
                                                                )
                                                )
                                                .creditorAccount(
                                                        new OBWriteDomestic2DataInitiationCreditorAccount()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("08080021325698")
                                                                .name("Mr Tim Burgess")
                                                                .secondaryIdentification("11")
                                                )
                                                .remittanceInformation(
                                                        new OBWriteDomestic2DataInitiationRemittanceInformation()
                                                                .unstructured("Internal ops code 5120103")
                                                                .reference("FRESCO-037")
                                                )
                                                .supplementaryData(new OBSupplementaryData1())
                                )
                                .authorisation(
                                        new OBWriteDomesticConsent4DataAuthorisation()
                                                .authorisationType(OBExternalAuthorisation1Code.ANY)
                                                .completionDateTime(DateTime.parse("2022-07-05T08:47:11+00:00"))
                                )
                                .scASupportData(
                                        new OBWriteDomesticConsent4DataSCASupportData()
                                                .requestedSCAExemptionType(OBRequestedSCAExemptionTypeEnum.BILLPAYMENT)
                                                .appliedAuthenticationApproach(OBAppliedAuthenticationApproachEnum.CA)
                                                .referencePaymentOrderId("b19b8b34-26e3-4434-b1a8-736cda5af4a6")
                                )
                ).risk(
                        new OBRisk1()
                                .paymentContextCode(OBExternalPaymentContext1Code.OTHER)
                                .merchantCategoryCode("mct1")
                                .merchantCustomerIdentification("merchantId123")
                                .contractPresentInidicator(null)
                                .beneficiaryPrepopulatedIndicator(null)
                                .paymentPurposeCode(null)
                                .beneficiaryAccountType(null)
                                .deliveryAddress(
                                        new OBRisk1DeliveryAddress()
                                                .addAddressLineItem("60 Queens Sq")
                                                .streetName("Queen Square")
                                                .buildingNumber("60")
                                                .postCode("BS1 1AA")
                                                .townName("Bristol")
                                                .countrySubDivision("en")
                                                .country("UK")
                                )
                )
                .links(null)
                .meta(null);
    }

    private static OBWriteInternationalConsentResponse6 getExpected_OBWriteInternationalConsentResponse6() {
        return new OBWriteInternationalConsentResponse6().data(
                        new OBWriteInternationalConsentResponse6Data()
                                .consentId("PIC_c69d5900-b814-4f8e-8e3b-101385390523")
                                .creationDateTime(DateTime.parse("2022-09-12T06:33:48.698Z"))
                                .status(OBWriteInternationalConsentResponse6Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-12T06:33:48.698Z"))
                                .readRefundAccount(OBReadRefundAccountEnum.NO)
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
                                .exchangeRateInformation(
                                        new OBWriteInternationalConsentResponse6DataExchangeRateInformation()
                                                .unitCurrency("EUR")
                                                .exchangeRate(BigDecimal.valueOf(10))
                                                .rateType(OBExchangeRateType2Code.AGREED)
                                                .contractIdentification("/tbill/2018/T102993")
                                                .expirationDateTime(null)
                                )
                                .initiation(
                                        new OBWriteInternational3DataInitiation()
                                                .instructionIdentification("ANSM020")
                                                .endToEndIdentification("FRESCO.21302.GFX.01")
                                                .localInstrument("UK.OBIE.BACS")
                                                .instructionPriority(OBPriority2Code.NORMAL)
                                                .purpose("CDCD")
                                                .extendedPurpose("Extended purpose")
                                                .chargeBearer(OBChargeBearerType1Code.SHARED)
                                                .currencyOfTransfer("EUR")
                                                .destinationCountryCode("GB")
                                                .instructedAmount(
                                                        new OBWriteDomestic2DataInitiationInstructedAmount()
                                                                .amount("10.01")
                                                                .currency("GBP")
                                                )
                                                .exchangeRateInformation(
                                                        new OBWriteInternational3DataInitiationExchangeRateInformation()
                                                                .unitCurrency("EUR")
                                                                .exchangeRate(BigDecimal.valueOf(10))
                                                                .rateType(OBExchangeRateType2Code.AGREED)
                                                                .contractIdentification("/tbill/2018/T102993")
                                                )
                                                .debtorAccount(
                                                        new OBWriteDomestic2DataInitiationDebtorAccount()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("11280001234567")
                                                                .name("Mr Shaun Ryder")
                                                                .secondaryIdentification("22")
                                                )
                                                .creditor(
                                                        new OBWriteInternational3DataInitiationCreditor()
                                                                .name("Creditor Name")
                                                                .postalAddress(
                                                                        new OBPostalAddress6()
                                                                                .addressType(OBAddressTypeCode.RESIDENTIAL)
                                                                                .department(null)
                                                                                .subDepartment(null)
                                                                                .streetName("The Mall")
                                                                                .buildingNumber("1")
                                                                                .postCode("WC1 1AB")
                                                                                .townName("London")
                                                                                .countrySubDivision(null)
                                                                                .country("UK")
                                                                                .addressLine(null)
                                                                )
                                                )
                                                .creditorAgent(
                                                        new OBWriteInternational3DataInitiationCreditorAgent()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("40400411270111")
                                                                .name("Creditor Agent Name")
                                                                .postalAddress(
                                                                        new OBPostalAddress6()
                                                                                .addressType(OBAddressTypeCode.RESIDENTIAL)
                                                                                .department(null)
                                                                                .subDepartment(null)
                                                                                .streetName("The Mall")
                                                                                .buildingNumber("1")
                                                                                .postCode("WC1 1AB")
                                                                                .townName("London")
                                                                                .countrySubDivision(null)
                                                                                .country("UK")
                                                                                .addressLine(null)
                                                                )
                                                )
                                                .creditorAccount(
                                                        new OBWriteDomestic2DataInitiationCreditorAccount()
                                                                .schemeName("UK.OBIE.SortCodeAccountNumber")
                                                                .identification("08080021325698")
                                                                .name("Mr Tim Burgess")
                                                                .secondaryIdentification("11")
                                                )
                                                .remittanceInformation(
                                                        new OBWriteDomestic2DataInitiationRemittanceInformation()
                                                                .unstructured("Internal ops code 5120103")
                                                                .reference("FRESCO-037")
                                                )
                                                .supplementaryData(
                                                        new OBSupplementaryData1()
                                                )
                                )
                                .authorisation(
                                        new OBWriteDomesticConsent4DataAuthorisation()
                                                .authorisationType(OBExternalAuthorisation1Code.ANY)
                                                .completionDateTime(DateTime.parse("2022-07-05T08:47:11+00:00"))
                                )
                                .scASupportData(
                                        new OBSCASupportData1()
                                                .requestedSCAExemptionType(OBRequestedSCAExemptionTypeEnum.BILLPAYMENT)
                                                .appliedAuthenticationApproach(OBAppliedAuthenticationApproachEnum.CA)
                                                .referencePaymentOrderId("b19b8b34-26e3-4434-b1a8-736cda5af4a6")
                                )
                                .debtor(null)
                ).risk(
                        new OBRisk1()
                                .paymentContextCode(OBExternalPaymentContext1Code.OTHER)
                                .merchantCategoryCode("mct1")
                                .merchantCustomerIdentification("merchantId123")
                                .contractPresentInidicator(null)
                                .beneficiaryPrepopulatedIndicator(null)
                                .paymentPurposeCode(null)
                                .beneficiaryAccountType(null)
                                .deliveryAddress(
                                        new OBRisk1DeliveryAddress()
                                                .addAddressLineItem("60 Queens Sq")
                                                .streetName("Queen Square")
                                                .buildingNumber("60")
                                                .postCode("BS1 1AA")
                                                .townName("Bristol")
                                                .countrySubDivision("en")
                                                .country("UK")
                                )
                )
                .links(null)
                .meta(null);
    }
}
