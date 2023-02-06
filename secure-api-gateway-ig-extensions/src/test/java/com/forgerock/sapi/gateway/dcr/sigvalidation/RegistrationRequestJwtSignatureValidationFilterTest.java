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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequestFactory;
import com.forgerock.sapi.gateway.dcr.sigvalidation.RegistrationRequestJwtSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier;
import com.forgerock.sapi.gateway.jwks.RestJwkSetServiceTest;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

class RegistrationRequestJwtSignatureValidationFilterTest {


    private static final String ERROR_DESCRIPTION = "Error Description";
    private Request request;
    private Handler handler = mock(Handler.class);

    private AttributesContext context;
    private static RegistrationRequestObjectFromJwtSupplier registrationObjectSupplier;
    private static RSASSASigner RSA_SIGNER;
    final private static String DIRECTORY_JWKS_URI = "https://keystore.openbankingtest.org.uk/keystore/openbanking.jwks";
    final private static String SOFTWARE_STATEMENT_JWKS_URI = "https://directory.softwareid.jwks_uri";
    private RegistrationRequestJwtSignatureValidationFilter filter;

    private final RegistrationRequestJwtSignatureValidationService dcrRegistrationRequestSignatureValidator
            = mock(RegistrationRequestJwtSignatureValidationService.class);
    private final SoftwareStatementAssertionSignatureValidatorService softwareStatementAssertionSignatureValidatorService = mock(SoftwareStatementAssertionSignatureValidatorService.class);

    @BeforeAll
    public static void beforeAll() throws NoSuchAlgorithmException {
        RSA_SIGNER = CryptoUtils.createRSASSASigner();
    }


    @BeforeEach
    void setUp() throws MalformedURLException {
        handler = mock(Handler.class);
        Map<URL, JWKSet> jwkSetByUrl = new HashMap();
        jwkSetByUrl.put(new URL(DIRECTORY_JWKS_URI), createJwkSet());
        jwkSetByUrl.put(new URL(SOFTWARE_STATEMENT_JWKS_URI), createJwkSet());
        this.request = new Request().setMethod("POST");
        filter = new RegistrationRequestJwtSignatureValidationFilter(
                softwareStatementAssertionSignatureValidatorService,
                dcrRegistrationRequestSignatureValidator);
        context = new AttributesContext(new RootContext());
    }

    @AfterEach
    void tearDown() {
        reset(handler, dcrRegistrationRequestSignatureValidator,
                softwareStatementAssertionSignatureValidatorService);
    }

      private JWKSet createJwkSet() {
        return new JWKSet(List.of(RestJwkSetServiceTest.createJWK(UUID.randomUUID().toString()),
                RestJwkSetServiceTest.createJWK(UUID.randomUUID().toString())));
    }

    /**
     * Uses nimbusds to create a SignedJWT and returns JWS object in its compact format consisting of
     * Base64URL-encoded parts delimited by period ('.') characters.
     *
     * @param claims      The claims to include in the signed jwt
     * @param signingAlgo the algorithm to use for signing
     * @return the jws in its compact form consisting of Base64URL-encoded parts delimited by period ('.') characters.
     */
    private String createEncodedJwtString(Map<String, Object> claims, JWSAlgorithm signingAlgo) {
        try {
            final SignedJWT signedJWT = new SignedJWT(new JWSHeader(signingAlgo), JWTClaimsSet.parse(claims));
            signedJWT.sign(RSA_SIGNER);
            return signedJWT.serialize();
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private SignedJwt createSignedJwt(Map<String, Object> claims, JWSAlgorithm signingAlgo) {
        String encodedJwsString = createEncodedJwtString(claims, signingAlgo);
        return new JwtReconstruction().reconstructJwt(encodedJwsString, SignedJwt.class);
    }

    @Test
    void filter_successSoftwareStatementWithJwskUri() throws Exception {
        // Given
        RegistrationRequest registrationRequest = RegistrationRequestFactory.getRegRequestWithJwksUriSoftwareStatement();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(softwareStatementAssertionSignatureValidatorService.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.get();

        // Then
        assert(response.getStatus()).isSuccessful();
        verify(handler, times(1)).handle(context, request);
    }

    @Test
    void filter_ResultContainsInvalidClientMetadataWhenNoContextAttribute() throws Exception {
        // Given
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(softwareStatementAssertionSignatureValidatorService.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.getOrThrow();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        verify(handler, never()).handle(context, request);
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenSignatureIsInvalid() throws Exception{
        // Given
        RegistrationRequest registrationRequest = RegistrationRequestFactory.getRegRequestWithJwksUriSoftwareStatement();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(softwareStatementAssertionSignatureValidatorService.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newExceptionPromise(
                        new DCRSignatureValidationException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT, "invalid jwt signature")));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).contains(DCRErrorCode.INVALID_SOFTWARE_STATEMENT.getCode());
        verify(handler, never()).handle(context, request);
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenRTEValidatingSSA() throws Exception{
        // Given
        RegistrationRequest registrationRequest = RegistrationRequestFactory.getRegRequestWithJwksUriSoftwareStatement();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(softwareStatementAssertionSignatureValidatorService.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newRuntimeExceptionPromise(
                    new DCRSignatureValidationRuntimeException("Runtime exception validating SSA")));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        verify(handler, never()).handle(null, request);
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenRegRequestSigInvalid() throws Exception {
        // Given
        RegistrationRequest registrationRequest = RegistrationRequestFactory.getRegRequestWithJwksUriSoftwareStatement();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(softwareStatementAssertionSignatureValidatorService.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newExceptionPromise(
                        new DCRSignatureValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, ERROR_DESCRIPTION)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).contains(ERROR_DESCRIPTION);
        verify(handler, never()).handle(null, request);
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenRTEValidatingRegRequestSig() throws Exception {
        // Given
        RegistrationRequest registrationRequest = RegistrationRequestFactory.getRegRequestWithJwksUriSoftwareStatement();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(softwareStatementAssertionSignatureValidatorService.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any(), any()))
                .thenReturn(Promises.newRuntimeExceptionPromise(
                        new DCRSignatureValidationRuntimeException(ERROR_DESCRIPTION)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        verify(handler, never()).handle(null, request);
    }
}