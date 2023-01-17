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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.request.DCRSignatureValidationException.ErrorCode;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;

class DCRRegistrationRequestJwtSignatureValidatorJwksTest {

    private DCRRegistrationRequestJwtSignatureValidatorJwks jwksJwtSignatureValidator;
    private final JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);
    private final TrustedDirectory ssaIssuingDirectory = mock(TrustedDirectory.class);
    private static RSASSASigner ssaSigner;
    private static final String TX_ID = "transactionId";

    @BeforeAll
    static void setUpClass() throws NoSuchAlgorithmException {
        ssaSigner = CryptoUtils.createRSASSASigner();
    }

    @BeforeEach
    void setUp() {
        jwksJwtSignatureValidator = new DCRRegistrationRequestJwtSignatureValidatorJwks(jwtSignatureValidator);
    }

    @AfterEach
    void tearDown() {
        reset(jwtSignatureValidator, ssaIssuingDirectory);
    }

    @Test
    void fails_WithRteWhenBadlyConfiguredTrustedDirectory(){
        // Given
        Map<String, Object> ssaClaimsMap = Map.of();
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        // When
        try {
           jwksJwtSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                            ssaClaimsSet, registrationRequestJwt);

            assertThat(false).isTrue();
        } catch (DCRSignatureValidationRuntimeException e){
            assertThat(e.getMessage()).isNotEmpty();
        }
    }

    @Test
    void fails_CantGetJwksSetEmptySsaClaim(){
        // Given
        Map<String, Object> ssaClaimsMap = Map.of();
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(ssaIssuingDirectory.getSoftwareStatementJwksClaimName()).thenReturn("jwks");

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksJwtSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                        ssaClaimsSet, registrationRequestJwt);

        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow, DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void fails_CantGetJwksUnparsableSsaClaim(){
        // Given
        Map<String, Object> ssaClaimsMap = Map.of("jwks", "gobbledy gook");
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(ssaIssuingDirectory.getSoftwareStatementJwksClaimName()).thenReturn("jwks");

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksJwtSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                        ssaClaimsSet, registrationRequestJwt);

        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow, DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void fails_jwtSignatureIsInvalid() throws SignatureException {
        // Given
        String ssaJwtString = DCRTestHelpers.VALID_SSA_FROM_IG;
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(ssaIssuingDirectory.getSoftwareStatementJwksClaimName()).thenReturn("software_jwks");
        doThrow(new SignatureException("Invalid jws signature")).when(jwtSignatureValidator)
                .validateSignature( eq(registrationRequestJwt), any(JWKSet.class));

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksJwtSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                        ssaClaimsSet, registrationRequestJwt);

        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow, DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_CLIENT_METADATA);
    }

    @Test
    void success_validateRegistrationRequestJwtSignature() throws ExecutionException, InterruptedException {
        // Given
        String ssaJwtString = DCRTestHelpers.VALID_SSA_FROM_IG;
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(ssaIssuingDirectory.getSoftwareStatementJwksClaimName()).thenReturn("software_jwks");

        // When
        Promise<Response, DCRSignatureValidationException> promise
                = jwksJwtSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, ssaIssuingDirectory,
                ssaClaimsSet, registrationRequestJwt);
        Response response = promise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
    }
}