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
package com.forgerock.sapi.gateway.dcr.sigvalidation;

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
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRSignatureValidationException.ErrorCode;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;

class RegistrationRequestJwtSignatureValidatorJwksUriTest {

    private RegistrationRequestJwtSignatureValidatorJwksUri jwksUriSignatureValidator;
    private final static JwkSetService jwkSetService = mock(JwkSetService.class);
    private final static JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);
    private final TrustedDirectory ssaIssuingDirectory = mock(TrustedDirectory.class);
    private static final String TX_ID = "transactionId";
    private static final String SSA_JWKS_URI_CLAIM_NAME = "software_jwks_endpoint";
    private static RSASSASigner ssaSigner;

    @BeforeAll
    static void setUpClass() throws NoSuchAlgorithmException {
        ssaSigner = CryptoUtils.createRSASSASigner();
    }

    @BeforeEach
    void setUp() {
        jwksUriSignatureValidator = new RegistrationRequestJwtSignatureValidatorJwksUri(jwkSetService,
                jwtSignatureValidator);
    }

    @AfterEach
    void tearDown() {
        reset(jwkSetService, jwtSignatureValidator, ssaIssuingDirectory);
    }

    @Test
    void failsBadlyConfiguredTrustedDirectory_validateRegistrationRequestJwtSignature() {
        // Given
        Map<String, Object> ssaClaimsMap = Map.of();
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        // Then
        Promise<Response, DCRSignatureValidationException> promise =
                jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                ssaClaimsSet, registrationRequestJwt);

        DCRSignatureValidationRuntimeException e =
                catchThrowableOfType(promise::getOrThrow, DCRSignatureValidationRuntimeException.class);
        assertThat(e.getMessage()).contains("has no softwareStatementJwksUriClaimName value");
    }

    @Test
    void failsEmptyJwksUriClaim_validateRegistrationRequestJwtSignature() {
        // Given
        Map<String, Object> ssaClaimsMap = Map.of();
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(ssaIssuingDirectory.getSoftwareStatementJwksUriClaimName()).thenReturn(SSA_JWKS_URI_CLAIM_NAME);

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                ssaClaimsSet, registrationRequestJwt);
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);

        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
        assertThat(exception.getErrorDescription()).contains("must contain a claim for the JWKS URI");
    }

    @Test
    void failsInvalidUriInJwksUriClaim_validateRegistrationRequestJwtSignature() {
        // Given
        Map<String, Object> ssaClaimsMap = Map.of(SSA_JWKS_URI_CLAIM_NAME, "not a uri");
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(ssaIssuingDirectory.getSoftwareStatementJwksUriClaimName()).thenReturn(SSA_JWKS_URI_CLAIM_NAME);

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                        ssaClaimsSet, registrationRequestJwt);
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);

        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
        assertThat(exception.getErrorDescription()).contains("must be a valid URL");
    }

    @Test
    void failsCantGetJwksSetFromUri_validateRegistrationRequestJwtSignature() throws MalformedURLException {
        // Given
        final String JWKS_URI = "https://jwks_uri.com";
        Map<String, Object> ssaClaimsMap = Map.of(SSA_JWKS_URI_CLAIM_NAME, JWKS_URI);
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(ssaIssuingDirectory.getSoftwareStatementJwksUriClaimName()).thenReturn(SSA_JWKS_URI_CLAIM_NAME);
        when(jwkSetService.getJwkSet(new URL(JWKS_URI))).thenReturn(Promises.newExceptionPromise(
                new FailedToLoadJWKException("Couldn't reach URL")));

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                        ssaClaimsSet, registrationRequestJwt);
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);

        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
        assertThat(exception.getErrorDescription()).contains("Failed to obtain jwks from software statement's " +
                "jwks_uri");
    }

    @Test
    void failsSignatureIsInvalid_validateRegistrationRequestJwtSignature()
            throws MalformedURLException, SignatureException {
        // Given
        final String JWKS_URI = "https://jwks_uri.com";
        Map<String, Object> ssaClaimsMap = Map.of(SSA_JWKS_URI_CLAIM_NAME, JWKS_URI);
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(ssaIssuingDirectory.getSoftwareStatementJwksUriClaimName()).thenReturn(SSA_JWKS_URI_CLAIM_NAME);
        JWKSet jwks = new JWKSet();
        when(jwkSetService.getJwkSet(new URL(JWKS_URI))).thenReturn(Promises.newResultPromise(jwks));
        doThrow(new SignatureException("Invalid Signature"))
                .when(jwtSignatureValidator).validateSignature(registrationRequestJwt, jwks);

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                        ssaClaimsSet, registrationRequestJwt);
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);

        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_CLIENT_METADATA);
        assertThat(exception.getErrorDescription()).contains("Failed to validate registration request signature " +
                "against jwkSet");
    }

    @Test
    void success_validateRegistrationRequestJwtSignature()
            throws InterruptedException, DCRSignatureValidationException, MalformedURLException {
        // Given
        final String JWKS_URI = "https://jwks_uri.com";
        Map<String, Object> ssaClaimsMap = Map.of(SSA_JWKS_URI_CLAIM_NAME, JWKS_URI);
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(ssaIssuingDirectory.getSoftwareStatementJwksUriClaimName()).thenReturn(SSA_JWKS_URI_CLAIM_NAME);
        JWKSet jwks = new JWKSet();
        when(jwkSetService.getJwkSet(new URL(JWKS_URI))).thenReturn(Promises.newResultPromise(jwks));

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                        ssaClaimsSet, registrationRequestJwt);
        Response response = promise.getOrThrow();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
    }
}