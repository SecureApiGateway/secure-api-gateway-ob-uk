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

import java.security.SignatureException;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

class RegistrationRequestJwtSignatureValidatorJwksTest {

    private RegistrationRequestJwtSignatureValidatorJwks jwksJwtSignatureValidator;
    private final JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);
    private final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
    private final SoftwareStatement softwareStatement = mock(SoftwareStatement.class);
    private static final String TX_ID = "transactionId";


    @BeforeEach
    void setUp() {
        jwksJwtSignatureValidator = new RegistrationRequestJwtSignatureValidatorJwks(jwtSignatureValidator);
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
    }

    @AfterEach
    void tearDown() {
        reset(jwtSignatureValidator, registrationRequest, softwareStatement);
    }

    @Test
    void fails_jwtSignatureIsInvalid() throws SignatureException {
        // Given
        SignedJwt signedJwt = CryptoUtils.createSignedJwt(Map.of(), JWSAlgorithm.PS256);
        JWKSet jwkSet = CryptoUtils.createJwkSet();

        // When
        when(registrationRequest.getSignedJwt()).thenReturn(signedJwt);
        when(softwareStatement.getJwksSet()).thenReturn(jwkSet);
        doThrow(new SignatureException("invalid jwt signature")).when(jwtSignatureValidator).validateSignature(signedJwt, jwkSet);
        Promise<Response, DCRSignatureValidationException> promise
                = jwksJwtSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID,
                registrationRequest);

       DCRSignatureValidationException exception = catchThrowableOfType(
               ()-> promise.getOrThrow(), DCRSignatureValidationException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
    }

    @Test
    void success_validateRegistrationRequestJwtSignature() throws ExecutionException, InterruptedException {
        // Given
        SignedJwt signedJwt = CryptoUtils.createSignedJwt(Map.of(), JWSAlgorithm.PS256);
        JWKSet jwkSet = CryptoUtils.createJwkSet();
        when(registrationRequest.getSignedJwt()).thenReturn(signedJwt);
        when(softwareStatement.getJwksSet()).thenReturn(jwkSet);

        // No need to mock validateSignature - it has a void return sign
        Promise<Response, DCRSignatureValidationException> promise
                = jwksJwtSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID, 
                registrationRequest);
        Response response = promise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
    }
}