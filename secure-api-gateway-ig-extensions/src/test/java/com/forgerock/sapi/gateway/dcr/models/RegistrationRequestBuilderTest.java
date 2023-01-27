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
package com.forgerock.sapi.gateway.dcr.models;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.forgerock.json.jose.jws.SignedJwt;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.common.jwt.ClaimsSetFacade;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRTestHelpers;
import com.forgerock.sapi.gateway.dcr.utils.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.jws.JwtReconstructionException;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;

class RegistrationRequestBuilderTest {

    private RegistrationRequestBuilder builder;
    private final SoftwareStatementBuilder softwareStatementBuilder = mock(SoftwareStatementBuilder.class);
    private final JwtDecoder jwtDecoder = mock(JwtDecoder.class);
    private final static String B64_ENCODED_REG_REQUEST_JWT = "header.payload.sig";
    private final static String TX_ID = "tx_id";
    private static RSASSASigner ssaSigner;

    @BeforeAll
    static void setUpClass() throws NoSuchAlgorithmException {
        ssaSigner = CryptoUtils.createRSASSASigner();
    }

    @BeforeEach
    void setUp() {
        builder = new RegistrationRequestBuilder(softwareStatementBuilder, jwtDecoder);
    }

    @AfterEach
    void tearDown() {
        reset(softwareStatementBuilder, jwtDecoder);
    }

    @Test
    void success_build() throws JwtReconstructionException, DCRRegistrationRequestBuilderException {
        // Given
        String softwareStatementb64EncodedString = "header.payload.sig";
        Map<String, Object> claims = Map.of("software_statement", softwareStatementb64EncodedString);
        SignedJwt regRequestSignedJwt = DCRTestHelpers.createSignedJwt(claims, JWSAlgorithm.PS256, ssaSigner);
        // When
        when(jwtDecoder.getSignedJwt(B64_ENCODED_REG_REQUEST_JWT)).thenReturn(regRequestSignedJwt);
        when(softwareStatementBuilder.buildSoftwareStatement(TX_ID, softwareStatementb64EncodedString)).thenReturn(
                new SoftwareStatement(regRequestSignedJwt, new ClaimsSetFacade(regRequestSignedJwt.getClaimsSet()))
        );
        RegistrationRequest registrationReqeuest = builder.build(TX_ID, B64_ENCODED_REG_REQUEST_JWT);

        // Then
        assertThat(registrationReqeuest).isNotNull();
        assertThat(registrationReqeuest.getSoftwareStatement()).isNotNull();
        assertThat(registrationReqeuest.getSignedJwt()).isEqualTo(regRequestSignedJwt);
    }

    @Test
    void throwsExceptionWhenInvalidEncodedJwtString() throws JwtReconstructionException {
        // Given

        // When
        when(jwtDecoder.getSignedJwt(B64_ENCODED_REG_REQUEST_JWT)).thenThrow(new JwtReconstructionException("invalid"));
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(
                ()->builder.build(TX_ID, B64_ENCODED_REG_REQUEST_JWT), DCRRegistrationRequestBuilderException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
    }

    @Test
    void throwsExceptionWhenNoSoftwareStatementClaimInRequestJwt() throws JwtReconstructionException {
        // Given
        Map<String, Object> claims = Map.of();
        SignedJwt regRequestSignedJwt = DCRTestHelpers.createSignedJwt(claims, JWSAlgorithm.PS256, ssaSigner);
        // When
        when(jwtDecoder.getSignedJwt(B64_ENCODED_REG_REQUEST_JWT)).thenReturn(regRequestSignedJwt);
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(
                ()->builder.build(TX_ID, B64_ENCODED_REG_REQUEST_JWT), DCRRegistrationRequestBuilderException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
    }

    @Test
    void throwsExceptionWhenSoftwareStatementBuilderFails()
            throws JwtReconstructionException, DCRRegistrationRequestBuilderException {
        // Given
        String softwareStatementb64EncodedString = "header.payload.sig";
        Map<String, Object> claims = Map.of("software_statement", softwareStatementb64EncodedString);
        SignedJwt regRequestSignedJwt = DCRTestHelpers.createSignedJwt(claims, JWSAlgorithm.PS256, ssaSigner);
        // When
        when(jwtDecoder.getSignedJwt(B64_ENCODED_REG_REQUEST_JWT)).thenReturn(regRequestSignedJwt);
        when(softwareStatementBuilder.buildSoftwareStatement(TX_ID, softwareStatementb64EncodedString)).thenThrow(
                new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_CLIENT_METADATA, "error"));

        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(
                ()->builder.build(TX_ID, B64_ENCODED_REG_REQUEST_JWT), DCRRegistrationRequestBuilderException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
    }
}