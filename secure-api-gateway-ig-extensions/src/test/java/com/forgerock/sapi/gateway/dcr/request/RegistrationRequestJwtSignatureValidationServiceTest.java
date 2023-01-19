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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.request.DCRSignatureValidationException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.utils.DCRUtils;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;

class RegistrationRequestJwtSignatureValidationServiceTest {

    private final TrustedDirectoryService trustedDirectoryService = mock(TrustedDirectoryService.class);
    private final DCRUtils dcrUtils = mock(DCRUtils.class);
    private final RegistrationRequestJwtSignatureValidatorJwks jwksSignatureValidator =
            mock(RegistrationRequestJwtSignatureValidatorJwks.class);
    private final RegistrationRequestJwtSignatureValidatorJwksUri jwksUriSignatureValidator =
            mock(RegistrationRequestJwtSignatureValidatorJwksUri.class);

    private final TrustedDirectory issuingDirectory = mock(TrustedDirectory.class);

    private final String X_FAPI_INTERACTION_ID = "34324-3432432-3432432";

    private static RSASSASigner ssaSigner;

    private RegistrationRequestJwtSignatureValidationService registrationRequestJwtSignatureValidator;

    @BeforeAll
    static void setUpClass() throws NoSuchAlgorithmException {
        ssaSigner = CryptoUtils.createRSASSASigner();
    }

    @BeforeEach
    void setUp() {
        registrationRequestJwtSignatureValidator = new RegistrationRequestJwtSignatureValidationService(
                trustedDirectoryService,
                dcrUtils,
                jwksSignatureValidator,
                jwksUriSignatureValidator);
    }

    @AfterEach
    void tearDown() {
        reset(jwksSignatureValidator, jwksUriSignatureValidator, trustedDirectoryService, issuingDirectory, dcrUtils);
    }

    @Test
    void success_validateRegistrationRequestJwtSignatureWithJwksUri() throws ExecutionException, InterruptedException, DCRSignatureValidationException {
        // Given
        String SSA_ISSUER = "anIssuer";
        Map<String, Object> ssaClaimsMap = Map.of("iss", SSA_ISSUER);
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(issuingDirectory.softwareStatementHoldsJwksUri()).thenReturn(true);
        when(issuingDirectory.getSoftwareStatementJwksClaimName()).thenReturn("claim_name");
        when(dcrUtils.getJwtIssuer("software statement assertion", ssaClaimsSet)).thenReturn(SSA_ISSUER);
        when(dcrUtils.getIssuingDirectory(trustedDirectoryService, SSA_ISSUER)).thenReturn(issuingDirectory);
        when(jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(anyString(), eq(issuingDirectory),
                eq(ssaClaimsSet), eq(registrationRequestJwt))).thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateRegistrationRequestJwtSignature(X_FAPI_INTERACTION_ID,
                ssaClaimsSet, registrationRequestJwt);

        // Then
        Response validationResponse = validationResponsePromise.get();
        assertThat(validationResponse.getStatus()).isEqualTo(Status.OK);
        verify(jwksSignatureValidator, never()).validateRegistrationRequestJwtSignature(any(), any(), any(), any());
    }

    @Test
    void validateFails_JwksUri() throws InterruptedException, DCRSignatureValidationException {
        // Given
        String SSA_ISSUER = "anIssuer";
        Map<String, Object> ssaClaimsMap = Map.of("iss", SSA_ISSUER);
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(issuingDirectory.softwareStatementHoldsJwksUri()).thenReturn(true);
        when(issuingDirectory.getSoftwareStatementJwksClaimName()).thenReturn("claim_name");
        when(dcrUtils.getJwtIssuer("software statement assertion", ssaClaimsSet)).thenReturn(SSA_ISSUER);
        when(dcrUtils.getIssuingDirectory(trustedDirectoryService, SSA_ISSUER)).thenReturn(issuingDirectory);
        when(jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(anyString(), eq(issuingDirectory),
                eq(ssaClaimsSet), eq(registrationRequestJwt))).thenReturn(Promises.newExceptionPromise(
                        new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, "invalid sig")));

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateRegistrationRequestJwtSignature(X_FAPI_INTERACTION_ID,
                        ssaClaimsSet, registrationRequestJwt);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(validationResponsePromise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
        verify(jwksSignatureValidator, never()).validateRegistrationRequestJwtSignature(any(), any(), any(), any());
    }


    @Test
    void success_validateRegistrationRequestJwtSignatureWithJwks() throws ExecutionException, InterruptedException, DCRSignatureValidationException {
        // Given
        String SSA_ISSUER = "anIssuer";
        Map<String, Object> ssaClaimsMap = Map.of("iss", SSA_ISSUER);
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(issuingDirectory.softwareStatementHoldsJwksUri()).thenReturn(false);
        when(dcrUtils.getJwtIssuer("software statement assertion", ssaClaimsSet)).thenReturn(SSA_ISSUER);
        when(dcrUtils.getIssuingDirectory(trustedDirectoryService, SSA_ISSUER)).thenReturn(issuingDirectory);
        when(jwksSignatureValidator.validateRegistrationRequestJwtSignature(anyString(), eq(issuingDirectory),
                eq(ssaClaimsSet), eq(registrationRequestJwt))).thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateRegistrationRequestJwtSignature(X_FAPI_INTERACTION_ID,
                        ssaClaimsSet, registrationRequestJwt);

        // Then
        Response validationResponse = validationResponsePromise.get();
        assertThat(validationResponse.getStatus()).isEqualTo(Status.OK);
        verify(jwksUriSignatureValidator, never()).validateRegistrationRequestJwtSignature(any(), any(), any(), any());
    }

    @Test
    void validateFails_Jwks() throws ExecutionException, InterruptedException, DCRSignatureValidationException {
        // Given
        String SSA_ISSUER = "anIssuer";
        Map<String, Object> ssaClaimsMap = Map.of("iss", SSA_ISSUER);
        String ssaJwtString = CryptoUtils.createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256, ssaSigner);
        Map<String, Object> registrationRequestClaimsMap = Map.of("software_statement", ssaJwtString);
        SignedJwt registrationRequestJwt = DCRTestHelpers.createSignedJwt(registrationRequestClaimsMap,
                JWSAlgorithm.PS256, ssaSigner);
        SignedJwt ssaJWt = new JwtReconstruction().reconstructJwt(ssaJwtString, SignedJwt.class);
        JwtClaimsSet ssaClaimsSet = ssaJWt.getClaimsSet();

        when(issuingDirectory.softwareStatementHoldsJwksUri()).thenReturn(false);
        when(dcrUtils.getJwtIssuer("software statement assertion", ssaClaimsSet)).thenReturn(SSA_ISSUER);
        when(dcrUtils.getIssuingDirectory(trustedDirectoryService, SSA_ISSUER)).thenReturn(issuingDirectory);
        when(jwksSignatureValidator.validateRegistrationRequestJwtSignature(anyString(), eq(issuingDirectory),
                eq(ssaClaimsSet), eq(registrationRequestJwt))).thenReturn(Promises.newExceptionPromise(
                new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, "invalid sig")));

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateRegistrationRequestJwtSignature(X_FAPI_INTERACTION_ID,
                        ssaClaimsSet, registrationRequestJwt);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(validationResponsePromise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_SOFTWARE_STATEMENT);
        verify(jwksUriSignatureValidator, never()).validateRegistrationRequestJwtSignature(any(), any(), any(), any());
    }

}