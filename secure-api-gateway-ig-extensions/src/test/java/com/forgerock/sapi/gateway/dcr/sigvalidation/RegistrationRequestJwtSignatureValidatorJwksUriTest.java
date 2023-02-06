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
import java.security.SignatureException;
import java.util.Map;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

class RegistrationRequestJwtSignatureValidatorJwksUriTest {

    private final static JwkSetService jwkSetService = mock(JwkSetService.class);
    private final static JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);
    private static final String TX_ID = "transactionId";
    private final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
    private final SoftwareStatement softwareStatement = mock(SoftwareStatement.class);
    private RegistrationRequestJwtSignatureValidatorJwksUri jwksUriSignatureValidator;

    @BeforeEach
    void setUp() {
        jwksUriSignatureValidator = new RegistrationRequestJwtSignatureValidatorJwksUri(jwkSetService,
                jwtSignatureValidator);
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.hasJwksUri()).thenReturn(true);
    }

    @AfterEach
    void tearDown() {
        reset(jwkSetService, jwtSignatureValidator, registrationRequest, softwareStatement);
    }

    @Test
    void failsCantGetJwksSetFromUri_validateRegistrationRequestJwtSignature() throws MalformedURLException {
        // Given
        final String JWKS_URI = "https://jwks_uri.com";
        final URL JWKS_URL = new URL(JWKS_URI);
        when(softwareStatement.getJwksUri()).thenReturn(JWKS_URL);
        when(jwkSetService.getJwkSet(JWKS_URL)).thenReturn(
                Promises.newExceptionPromise(new FailedToLoadJWKException("Couldn't load JWKS")));

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID,
                        registrationRequest);
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);

        // Then
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
        assertThat(exception.getErrorDescription()).contains("Failed to obtain jwks from software statement's " +
                "jwks_uri");
    }

    @Test
    void failsSignatureIsInvalid_validateRegistrationRequestJwtSignature()
            throws MalformedURLException, SignatureException {
        // Given
        final String JWKS_URI = "https://jwks_uri.com";
        final URL JWKS_URL = new URL(JWKS_URI);
        when(softwareStatement.getJwksUri()).thenReturn(JWKS_URL);
        JWKSet jwks = new JWKSet();
        when(jwkSetService.getJwkSet(JWKS_URL)).thenReturn(Promises.newResultPromise(jwks));
        SignedJwt registrationRequestJwt = CryptoUtils.createSignedJwt(Map.of(), JWSAlgorithm.PS256);
        when(registrationRequest.getSignedJwt()).thenReturn(registrationRequestJwt);
        doThrow(new SignatureException("Invalid Signature"))
                .when(jwtSignatureValidator).validateSignature(registrationRequestJwt, jwks);

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID,
                        registrationRequest);
        DCRSignatureValidationException exception = catchThrowableOfType(promise::getOrThrow,
                DCRSignatureValidationException.class);

        // Then
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_CLIENT_METADATA);
        assertThat(exception.getErrorDescription()).contains("Failed to validate registration request signature " +
                "against jwkSet");
    }

    @Test
    void success_validateRegistrationRequestJwtSignature()
            throws InterruptedException, DCRSignatureValidationException, MalformedURLException {
        // Given
        final String JWKS_URI = "https://jwks_uri.com";
        final URL JWKS_URL = new URL(JWKS_URI);
        when(softwareStatement.getJwksUri()).thenReturn(JWKS_URL);
        JWKSet jwks = new JWKSet();
        when(jwkSetService.getJwkSet(JWKS_URL)).thenReturn(Promises.newResultPromise(jwks));

        // When
        Promise<Response, DCRSignatureValidationException> promise =
                jwksUriSignatureValidator.validateRegistrationRequestJwtSignature(TX_ID,
                        registrationRequest);
        Response response = promise.getOrThrow();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.OK);
    }
}