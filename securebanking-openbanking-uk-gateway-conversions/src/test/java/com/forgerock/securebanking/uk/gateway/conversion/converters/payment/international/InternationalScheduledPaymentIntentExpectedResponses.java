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

public class InternationalScheduledPaymentIntentExpectedResponses {
    private static OBWriteInternationalScheduledConsentResponse5 _OBWriteInternationalScheduledConsentResponse5;
    private static OBWriteInternationalScheduledConsentResponse6 _OBWriteInternationalScheduledConsentResponse6;

    public static OBWriteInternationalScheduledConsentResponse5 getExpectedOBWriteInternationalScheduledConsentResponse5() {
        if (Objects.isNull(_OBWriteInternationalScheduledConsentResponse5)) {
            _OBWriteInternationalScheduledConsentResponse5 = getExpected_OBWriteInternationalScheduledConsentResponse5();
        }
        return _OBWriteInternationalScheduledConsentResponse5;
    }

    public static OBWriteInternationalScheduledConsentResponse6 getExpectedOBWriteInternationalScheduledConsentResponse6() {
        if (Objects.isNull(_OBWriteInternationalScheduledConsentResponse6)) {
            _OBWriteInternationalScheduledConsentResponse6 = getExpected_OBWriteInternationalScheduledConsentResponse6();
        }
        return _OBWriteInternationalScheduledConsentResponse6;
    }

    private static OBWriteInternationalScheduledConsentResponse5 getExpected_OBWriteInternationalScheduledConsentResponse5() {
        return new OBWriteInternationalScheduledConsentResponse5().data(
                        new OBWriteInternationalScheduledConsentResponse5Data()
                                .consentId("PISC_5bb11395-3b4a-4edd-9726-518c23e7be88")
                                .creationDateTime(DateTime.parse("2022-09-12T06:36:43.430Z"))
                                .status(OBWriteInternationalScheduledConsentResponse5Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-12T06:36:43.430Z"))
                                .permission(OBExternalPermissions2Code.CREATE)
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
                                        new OBWriteInternationalScheduled3DataInitiation()
                                                .instructionIdentification("ANSM020")
                                                .endToEndIdentification("FRESCO.21302.GFX.01")
                                                .localInstrument("UK.OBIE.BACS")
                                                .instructionPriority(OBPriority2Code.URGENT)
                                                .purpose("CDCD")
                                                .extendedPurpose("Extended purpose")
                                                .chargeBearer(OBChargeBearerType1Code.SHARED)
                                                .requestedExecutionDateTime(DateTime.parse("2022-09-21T08:46:53+00:00"))
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
                                                .completionDateTime(DateTime.parse("2022-07-20T08:46:53+00:00"))
                                )
                                .scASupportData(
                                        new OBWriteDomesticConsent4DataSCASupportData()
                                                .requestedSCAExemptionType(OBRequestedSCAExemptionTypeEnum.BILLPAYMENT)
                                                .appliedAuthenticationApproach(OBAppliedAuthenticationApproachEnum.CA)
                                                .referencePaymentOrderId("8c15fac9-6b7f-4ea3-902a-74093673648a")
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

    private static OBWriteInternationalScheduledConsentResponse6 getExpected_OBWriteInternationalScheduledConsentResponse6() {
        return new OBWriteInternationalScheduledConsentResponse6().data(
                        new OBWriteInternationalScheduledConsentResponse6Data()
                                .consentId("PISC_d1b0b65e-3c8f-4a11-8cc2-c61bf449a5f8")
                                .creationDateTime(DateTime.parse("2022-09-12T06:35:46.487Z"))
                                .status(OBWriteInternationalScheduledConsentResponse6Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-12T06:35:46.487Z"))
                                .permission(OBExternalPermissions2Code.CREATE)
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
                                        new OBWriteInternationalScheduledConsentResponse6DataInitiation()
                                                .instructionIdentification("ANSM020")
                                                .endToEndIdentification("FRESCO.21302.GFX.01")
                                                .localInstrument("UK.OBIE.BACS")
                                                .instructionPriority(OBPriority2Code.URGENT)
                                                .purpose("CDCD")
                                                .extendedPurpose("Extended purpose")
                                                .chargeBearer(OBChargeBearerType1Code.SHARED)
                                                .requestedExecutionDateTime(DateTime.parse("2022-09-21T08:46:53+00:00"))
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
                                                        new OBWriteInternationalScheduledConsentResponse6DataInitiationCreditor()
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
                                                .completionDateTime(DateTime.parse("2022-07-20T08:46:53+00:00"))
                                )
                                .scASupportData(
                                        new OBSCASupportData1()
                                                .requestedSCAExemptionType(OBRequestedSCAExemptionTypeEnum.BILLPAYMENT)
                                                .appliedAuthenticationApproach(OBAppliedAuthenticationApproachEnum.CA)
                                                .referencePaymentOrderId("8c15fac9-6b7f-4ea3-902a-74093673648a")
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
