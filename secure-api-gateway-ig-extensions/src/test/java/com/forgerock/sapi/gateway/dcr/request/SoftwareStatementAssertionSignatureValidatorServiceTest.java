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
package com.forgerock.sapi.gateway.dcr.request;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Map;

import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.request.DCRSignatureValidationException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.utils.DCRUtils;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;

class SoftwareStatementAssertionSignatureValidatorServiceTest {

    private SoftwareStatementAssertionSignatureValidatorService ssaSigValidator;
    private static final TrustedDirectoryService trustedDirectoryService = mock(TrustedDirectoryService.class);
    private static final TrustedDirectory ssaIssuingTrustedDirectory = mock(TrustedDirectory.class);
    private static final JwkSetService jwkSetService = mock(JwkSetService.class);
    private static final JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);
    private static final DCRUtils dcrUtils = new DCRUtils();
    private static final String TX_ID = "transactionId";
    private static final String SSA_ISSUER = "Acme Trusted Directory";
    private static RSASSASigner ssaSigner;

    @BeforeAll
    static void setUpClass() throws NoSuchAlgorithmException {
        ssaSigner = CryptoUtils.createRSASSASigner();
    }

    @BeforeEach
    void setUp() {
        ssaSigValidator = new SoftwareStatementAssertionSignatureValidatorService(trustedDirectoryService, jwkSetService,
                jwtSignatureValidator, dcrUtils);
    }

    @AfterEach
    void tearDown() {
        reset(trustedDirectoryService, ssaIssuingTrustedDirectory, jwkSetService, jwtSignatureValidator);
    }

    @Test
    void failIfNotValidIssuer_validateSoftwareStatementAssertionSignature() {
        // Given
        SignedJwt ssaSignedJwt = DCRTestHelpers.createSignedJwt(Map.of(), JWSAlgorithm.PS256, ssaSigner);

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                ssaSigValidator.validateSoftwareStatementAssertionSignature(TX_ID, ssaSignedJwt);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failIfNoTrustedDirectoryForIssuer_validateSoftwareStatementAssertionSignature() {
        // Given
        SignedJwt ssaSignedJwt = DCRTestHelpers.createSignedJwt(Map.of("iss", SSA_ISSUER),
                JWSAlgorithm.PS256, ssaSigner);

        // When
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(SSA_ISSUER)).thenReturn(null);
        Promise<Response, DCRSignatureValidationException> promise =
                ssaSigValidator.validateSoftwareStatementAssertionSignature(TX_ID, ssaSignedJwt);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.UNAPPROVED_SOFTWARE_STATEMENT);
    }

    @Test
    void failIfBadlyConfiguredTrustedDirectoryNoDirectoryJwks_validateSoftwareStatementAssertionSignature() {
        // Given
        SignedJwt ssaSignedJwt = DCRTestHelpers.createSignedJwt(Map.of("iss", SSA_ISSUER),
                JWSAlgorithm.PS256, ssaSigner);

        // When
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(SSA_ISSUER))
                .thenReturn(ssaIssuingTrustedDirectory);
        when(ssaIssuingTrustedDirectory.getDirectoryJwksUri()).thenReturn(null);
        Promise<Response, DCRSignatureValidationException> promise =
                ssaSigValidator.validateSoftwareStatementAssertionSignature(TX_ID, ssaSignedJwt);

        // Then
        DCRSignatureValidationRuntimeException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationRuntimeException.class);
        assertThat(exception.getMessage()).contains("directoryJwksUri");
    }

    @Test
    void failIfBadlyConfiguredTrustedDirectoryDirectoryJwksNotUrl_validateSoftwareStatementAssertionSignature() {
        // Given
        SignedJwt ssaSignedJwt = DCRTestHelpers.createSignedJwt(Map.of("iss", SSA_ISSUER),
                JWSAlgorithm.PS256, ssaSigner);

        // When
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(SSA_ISSUER))
                .thenReturn(ssaIssuingTrustedDirectory);
        when(ssaIssuingTrustedDirectory.getDirectoryJwksUri()).thenReturn("not a url");
        Promise<Response, DCRSignatureValidationException> promise =
                ssaSigValidator.validateSoftwareStatementAssertionSignature(TX_ID, ssaSignedJwt);

        // Then
        DCRSignatureValidationRuntimeException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationRuntimeException.class);
        assertThat(exception.getMessage()).contains("must be a valid URL");
    }

    @Test
    void failIfJwkSetServiceCantGetJwkSet_validateSoftwareStatementAssertionSignature() throws MalformedURLException {
        // Given
        SignedJwt ssaSignedJwt = DCRTestHelpers.createSignedJwt(Map.of("iss", SSA_ISSUER),
                JWSAlgorithm.PS256, ssaSigner);
        final String JWK_SET_URL_STR = "https://jwkset.com";
        final URL JWK_SET_URL = new URL(JWK_SET_URL_STR);

        // When
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(SSA_ISSUER))
                .thenReturn(ssaIssuingTrustedDirectory);
        when(ssaIssuingTrustedDirectory.getDirectoryJwksUri()).thenReturn(JWK_SET_URL_STR);
        when(jwkSetService.getJwkSet(JWK_SET_URL)).thenReturn(
                Promises.newExceptionPromise(new FailedToLoadJWKException("No jwkset")));
        Promise<Response, DCRSignatureValidationException> promise =
                ssaSigValidator.validateSoftwareStatementAssertionSignature(TX_ID, ssaSignedJwt);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getMessage()).contains(JWK_SET_URL_STR);
    }

    @Test
    void failIfSignatureInvalid_validateSoftwareStatementAssertionSignature() throws Exception {
        // Given
        SignedJwt ssaSignedJwt = DCRTestHelpers.createSignedJwt(Map.of("iss", SSA_ISSUER),
                JWSAlgorithm.PS256, ssaSigner);
        final String JWK_SET_URL_STR = "https://jwkset.com";
        final URL JWK_SET_URL = new URL(JWK_SET_URL_STR);
        final JWKSet JWKS_SET = new JWKSet();
        // When
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(SSA_ISSUER))
                .thenReturn(ssaIssuingTrustedDirectory);
        when(ssaIssuingTrustedDirectory.getDirectoryJwksUri()).thenReturn(JWK_SET_URL_STR);
        when(jwkSetService.getJwkSet(JWK_SET_URL)).thenReturn(
                Promises.newResultPromise(JWKS_SET));
        doThrow(new SignatureException("Invalid sig")).when(jwtSignatureValidator)
                .validateSignature(ssaSignedJwt, JWKS_SET);

        Promise<Response, DCRSignatureValidationException> promise =
                ssaSigValidator.validateSoftwareStatementAssertionSignature(TX_ID, ssaSignedJwt);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getMessage()).contains("Failed to validate SSA");
    }
}