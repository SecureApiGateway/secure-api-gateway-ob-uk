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
package com.forgerock.sapi.gateway.dcr.utils;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRSignatureValidationException;
import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRSignatureValidationException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRTestHelpers;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryOpenBankingTest;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;

class DCRUtilsTest {

    private DCRUtils dcrUtils;
    private static RSASSASigner ssaSigner;

    private final static  String SSA_ISSUER = "ssa_issuer";

    @BeforeAll
    static void setUpClass() throws NoSuchAlgorithmException {
        ssaSigner = CryptoUtils.createRSASSASigner();
    }

    @BeforeEach
    void setUp() {
        dcrUtils = new DCRUtils();
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void success_getJwtIssuer() throws DCRSignatureValidationException {
        // Given
        final String JWT_NAME = "software_statement";
        final JwtClaimsSet jwtClaimsSet = new JwtClaimsSet();
        jwtClaimsSet.setIssuer(SSA_ISSUER);
        // When
        String issuer = dcrUtils.getJwtIssuer(JWT_NAME, jwtClaimsSet);
        // Then
        assertThat(issuer).isEqualTo(SSA_ISSUER);
    }

    @Test
    void failsNoIssuerClaim_getJwtIssuer() throws DCRSignatureValidationException {
        // Given
        final String JWT_NAME = "software_statement";
        final JwtClaimsSet jwtClaimsSet = new JwtClaimsSet();
        // When
        DCRSignatureValidationException exception = catchThrowableOfType(
                () -> dcrUtils.getJwtIssuer(JWT_NAME, jwtClaimsSet), DCRSignatureValidationException.class);
        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void success_GetJwtIssuer() throws DCRSignatureValidationException {
        // Given
        final String JWT_NAME = "software_statement";
        Map<String, Object> ssaClaimsMap = Map.of("iss", SSA_ISSUER);
        SignedJwt signedJwt = DCRTestHelpers.createSignedJwt(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        // When
        String issuer = dcrUtils.getJwtIssuer(JWT_NAME, signedJwt);
        // Then
        assertThat(issuer).isEqualTo(SSA_ISSUER);
    }

    @Test
    void failsNoIssuer_GetJwtIssuer()  {
        // Given
        final String JWT_NAME = "software_statement";
        Map<String, Object> ssaClaimsMap = Map.of();
        SignedJwt signedJwt = DCRTestHelpers.createSignedJwt(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        // When
        DCRSignatureValidationException exception = catchThrowableOfType(
                () -> dcrUtils.getJwtIssuer(JWT_NAME, signedJwt), DCRSignatureValidationException.class);
        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void success_getIssuingDirectory() throws DCRSignatureValidationException {
        // Given
        TrustedDirectoryService trustedDirectoryService = mock(TrustedDirectoryService.class);
        TrustedDirectory openBankingTestTrustedDirectory = new TrustedDirectoryOpenBankingTest();
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(SSA_ISSUER))
                .thenReturn( openBankingTestTrustedDirectory);
        // When
        TrustedDirectory trustedDirectory = dcrUtils.getIssuingDirectory(trustedDirectoryService, SSA_ISSUER);

        // Then
        assertThat(trustedDirectory).isEqualTo(openBankingTestTrustedDirectory);
    }

    @Test
    void failsNoDirectoryForIssuer_getIssuingDirectory() throws DCRSignatureValidationException {
        // Given
        TrustedDirectoryService trustedDirectoryService = mock(TrustedDirectoryService.class);
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(SSA_ISSUER))
                .thenReturn( null);
        // When
        DCRSignatureValidationException exception = catchThrowableOfType(
                () ->dcrUtils.getIssuingDirectory(trustedDirectoryService, SSA_ISSUER),
                DCRSignatureValidationException.class);

        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.UNAPPROVED_SOFTWARE_STATEMENT);
    }

}