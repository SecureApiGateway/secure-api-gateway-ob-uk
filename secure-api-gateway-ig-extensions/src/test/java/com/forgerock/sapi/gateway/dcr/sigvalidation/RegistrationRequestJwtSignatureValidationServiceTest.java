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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.ExecutionException;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;

class RegistrationRequestJwtSignatureValidationServiceTest {

    private final RegistrationRequestJwtSignatureValidatorJwks jwksSignatureValidator =
            mock(RegistrationRequestJwtSignatureValidatorJwks.class);
    private final RegistrationRequestJwtSignatureValidatorJwksUri jwksUriSignatureValidator =
            mock(RegistrationRequestJwtSignatureValidatorJwksUri.class);

    private final String X_FAPI_INTERACTION_ID = "34324-3432432-3432432";
    private final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
    private final SoftwareStatement softwareStatement = mock(SoftwareStatement.class);
    private RegistrationRequestJwtSignatureValidationService registrationRequestJwtSignatureValidator;

    @BeforeEach
    void setUp() {
        registrationRequestJwtSignatureValidator = new RegistrationRequestJwtSignatureValidationService(
                jwksSignatureValidator,
                jwksUriSignatureValidator);
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
    }

    @AfterEach
    void tearDown() {
        reset(jwksSignatureValidator, jwksUriSignatureValidator, registrationRequest, softwareStatement);
    }

    @Test
    void success_validateRegistrationRequestJwtSignatureWithJwksUri() throws ExecutionException, InterruptedException {
        // Given
        when(softwareStatement.hasJwksUri()).thenReturn(true);
        when(jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(anyString(),
                eq(registrationRequest))).thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateJwtSignature(X_FAPI_INTERACTION_ID,
                registrationRequest);

        // Then
        Response validationResponse = validationResponsePromise.get();
        assertThat(validationResponse.getStatus()).isEqualTo(Status.OK);
        verify(jwksUriSignatureValidator, times(1)).validateRegistrationRequestJwtSignature(any(), any());
        verify(jwksSignatureValidator, never()).validateRegistrationRequestJwtSignature(any(), any());
    }

    @Test
    void validateFails_JwksUri(){
        // Given
        when(softwareStatement.hasJwksUri()).thenReturn(true);
        when(jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(anyString(),
                eq(registrationRequest))).thenReturn(Promises.newExceptionPromise(
                        new DCRSignatureValidationException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT, "invalid sig")));

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateJwtSignature(X_FAPI_INTERACTION_ID,
                        registrationRequest);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(validationResponsePromise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
        verify(jwksSignatureValidator, never()).validateRegistrationRequestJwtSignature(any(), any());
    }


    @Test
    void success_validateRegistrationRequestJwtSignatureWithJwks() throws ExecutionException, InterruptedException {
        // Given
        when(jwksSignatureValidator.validateRegistrationRequestJwtSignature(anyString(),
                eq(registrationRequest))).thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        when(softwareStatement.hasJwksUri()).thenReturn(false);

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateJwtSignature(X_FAPI_INTERACTION_ID,
                        registrationRequest);

        // Then
        Response validationResponse = validationResponsePromise.get();
        assertThat(validationResponse.getStatus()).isEqualTo(Status.OK);
        verify(jwksSignatureValidator, times(1)).validateRegistrationRequestJwtSignature(any(), any());
        verify(jwksUriSignatureValidator, never()).validateRegistrationRequestJwtSignature(any(), any());
    }

    @Test
    void validateFails_Jwks() {
        // Given
        when(softwareStatement.hasJwksUri()).thenReturn(false);
        when(jwksSignatureValidator.validateRegistrationRequestJwtSignature(anyString(),
                eq(registrationRequest))).thenReturn(Promises.newExceptionPromise(
                new DCRSignatureValidationException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT, "invalid sig")));

        // When
        Promise<Response, DCRSignatureValidationException> validationResponsePromise =
                registrationRequestJwtSignatureValidator.validateJwtSignature(X_FAPI_INTERACTION_ID,
                        registrationRequest);

        // Then
        DCRSignatureValidationException exception = catchThrowableOfType(validationResponsePromise::getOrThrow,
                DCRSignatureValidationException.class);
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
        verify(jwksSignatureValidator, times(1)).validateRegistrationRequestJwtSignature(any(), any());
        verify(jwksUriSignatureValidator, never()).validateRegistrationRequestJwtSignature(any(), any());
    }

}