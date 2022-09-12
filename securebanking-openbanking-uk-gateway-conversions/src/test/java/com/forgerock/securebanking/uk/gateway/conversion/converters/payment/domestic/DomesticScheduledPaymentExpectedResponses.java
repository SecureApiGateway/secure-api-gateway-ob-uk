package com.forgerock.securebanking.uk.gateway.conversion.converters.payment.domestic;

import org.joda.time.DateTime;
import uk.org.openbanking.datamodel.common.*;
import uk.org.openbanking.datamodel.payment.*;

import java.util.List;
import java.util.Objects;

public class DomesticScheduledPaymentExpectedResponses {

    private static OBWriteDomesticScheduledConsentResponse4 _OBWriteDomesticScheduledConsentResponse4;
    private static OBWriteDomesticScheduledConsentResponse5 _OBWriteDomesticScheduledConsentResponse5;

    public static OBWriteDomesticScheduledConsentResponse4 getExpectedOBWriteDomesticScheduledConsentResponse4() {
        if (Objects.isNull(_OBWriteDomesticScheduledConsentResponse4)) {
            _OBWriteDomesticScheduledConsentResponse4 = getExpected_OBWriteDomesticScheduledConsentResponse4();
        }
        return _OBWriteDomesticScheduledConsentResponse4;
    }

    public static OBWriteDomesticScheduledConsentResponse5 getExpectedOBWriteDomesticScheduledConsentResponse5() {
        if (Objects.isNull(_OBWriteDomesticScheduledConsentResponse5)) {
            _OBWriteDomesticScheduledConsentResponse5 = getExpected_OBWriteDomesticScheduledConsentResponse5();
        }
        return _OBWriteDomesticScheduledConsentResponse5;
    }

    private static OBWriteDomesticScheduledConsentResponse4 getExpected_OBWriteDomesticScheduledConsentResponse4() {
        return new OBWriteDomesticScheduledConsentResponse4().data(
                        new OBWriteDomesticScheduledConsentResponse4Data()
                                .consentId("PDSC_e9d72962-2d5d-4f2f-8392-d5961d20fc88")
                                .creationDateTime(DateTime.parse("2022-09-09T15:51:30.487Z"))
                                .status(OBWriteDomesticScheduledConsentResponse4Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-09T15:51:30.487Z"))
                                .permission(null)
                                .readRefundAccount(null)
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
                                        new OBWriteDomesticScheduled2DataInitiation()
                                                .instructionIdentification("ACME412")
                                                .endToEndIdentification("FRESCO.21302.GFX.20")
                                                .localInstrument(null)
                                                .requestedExecutionDateTime(DateTime.parse("2022-10-30T15:15:13+00:00"))
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

    private static OBWriteDomesticScheduledConsentResponse5 getExpected_OBWriteDomesticScheduledConsentResponse5() {
        return new OBWriteDomesticScheduledConsentResponse5().data(
                        new OBWriteDomesticScheduledConsentResponse5Data()
                                .consentId("PDSC_721f791e-fc89-4198-9148-642812d873e9")
                                .creationDateTime(DateTime.parse("2022-09-09T15:52:32.519Z"))
                                .status(OBWriteDomesticScheduledConsentResponse5Data.StatusEnum.AWAITINGAUTHORISATION)
                                .statusUpdateDateTime(DateTime.parse("2022-09-09T15:52:32.519Z"))
                                .permission(null)
                                .readRefundAccount(null)
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
                                        new OBWriteDomesticScheduled2DataInitiation()
                                                .instructionIdentification("ACME412")
                                                .endToEndIdentification("FRESCO.21302.GFX.20")
                                                .localInstrument(null)
                                                .requestedExecutionDateTime(DateTime.parse("2022-10-30T15:15:13+00:00"))
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
