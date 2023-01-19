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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.request.DCRSignatureValidationException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.utils.DCRUtils;
import com.forgerock.sapi.gateway.jwks.RestJwkSetServiceTest;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.forgerock.sapi.gateway.dcr.request.RegistrationRequestJwtSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier;

class RegistrationRequestJwtSignatureValidationFilterTest {


    private static final String ERROR_DESCRIPTION = "Error Description";
    private Request request;
    private Handler handler = mock(Handler.class);
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
        RSA_SIGNER = createRSASSASigner();
    }

    /**
     * JWT signer which uses generated test RSA private key
     */
    private static RSASSASigner createRSASSASigner() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new RSASSASigner(pair.getPrivate());
    }

    @BeforeEach
    void setUp() throws MalformedURLException {
        registrationObjectSupplier = mock(RegistrationRequestObjectFromJwtSupplier.class);
        handler = mock(Handler.class);
        Map<URL, JWKSet> jwkSetByUrl = new HashMap();
        jwkSetByUrl.put(new URL(DIRECTORY_JWKS_URI), createJwkSet());
        jwkSetByUrl.put(new URL(SOFTWARE_STATEMENT_JWKS_URI), createJwkSet());
        this.request = new Request().setMethod("POST");
        DCRUtils dcrUtils = new DCRUtils();
        filter = new RegistrationRequestJwtSignatureValidationFilter(
                registrationObjectSupplier,
                List.of("PS256"),
                dcrUtils,
                softwareStatementAssertionSignatureValidatorService,
                dcrRegistrationRequestSignatureValidator);
    }

    @AfterEach
    void tearDown() {
        reset(handler,  registrationObjectSupplier, dcrRegistrationRequestSignatureValidator, softwareStatementAssertionSignatureValidatorService);
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
        Map<String, Object> ssaClaimsMap = Map.of();
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);

        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);

        when(softwareStatementAssertionSignatureValidatorService.validateSoftwareStatementAssertionSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateRegistrationRequestJwtSignature(any(), any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assert(response.getStatus()).isSuccessful();
        verify(handler, times(1)).handle(null, request);
    }

    @Test
    void filter_ResultContainsInvalidClientMetadataWhenNoRequestObject() throws Exception {
        // Given
        RegistrationRequestJwtSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier mockRegistrationObjectSupplier
                = mock(RegistrationRequestJwtSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier.class);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(null);
        DCRUtils dcrUtils = new DCRUtils();
        filter = new RegistrationRequestJwtSignatureValidationFilter(
                mockRegistrationObjectSupplier, List.of("PS256"), dcrUtils, softwareStatementAssertionSignatureValidatorService, dcrRegistrationRequestSignatureValidator);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).contains("must contain a signed request jwt");
        verify(handler, never()).handle(null, request);
    }

    @Test
    void filter_ResultContainsInvalidClientMetadataWhenEmptyRegistrationRequest() throws Exception {
        // Given
        Map<String, Object> registrationRequestJwtClaims = Map.of();
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                DCRSignatureValidationException.ErrorCode.INVALID_CLIENT_METADATA.toString());
        assertThat(responseBody.get("error_description")).contains("registration request jwt must contain 'software_statement' claim");
    }

    @Test
    void filter_ResultContainsInvalidClientMetadataWhenInvalidSSAInRegistrationRequest() throws Exception {
        // Given
        String invalidEncodedSsaJwtString = "324FA.324BC.AAAAAA";
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", invalidEncodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                DCRSignatureValidationException.ErrorCode.INVALID_CLIENT_METADATA.toString());
        assertThat(responseBody.get("error_description")).contains("Badly formed b64 encoded software statement");
    }

    @Test
    void filter_ResultContainsInvalidClientMetadataWhenInvalidSigningAlgorithmInRegistrationRequest() throws Exception {
        // Given
        Map<String, Object> ssaClaimsMap = Map.of();
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.RS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                DCRSignatureValidationException.ErrorCode.INVALID_CLIENT_METADATA.toString());
        assertThat(responseBody.get("error_description")).contains("DCR request JWT must be signed with one of");
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenNoSoftwareStatement() throws Exception {
        // Given
        SignedJwt signedJwt = createSignedJwt(Map.of(), JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.INVALID_CLIENT_METADATA.toString());
        assertThat(responseBody.get("error_description")).contains("registration request jwt must contain " +
                "'software_statement' claim");
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenSignatureIsInvalid() throws Exception{
        // Given
        Map<String, Object> ssaClaimsMap = Map.of();
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);

        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        final String ERROR_DESCRIPTION = "description";
        when(softwareStatementAssertionSignatureValidatorService.validateSoftwareStatementAssertionSignature(any(), any()))
                .thenReturn(Promises.newExceptionPromise(
                        new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, ERROR_DESCRIPTION)));


        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).contains(ERROR_DESCRIPTION);
        verify(handler, never()).handle(null, request);
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenRTEValidatingSSA() throws Exception{
        // Given
        Map<String, Object> ssaClaimsMap = Map.of();
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);

        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        final String ERROR_DESCRIPTION = "description";
        when(softwareStatementAssertionSignatureValidatorService.validateSoftwareStatementAssertionSignature(any(), any()))
                .thenReturn(Promises.newRuntimeExceptionPromise(
                    new DCRSignatureValidationRuntimeException("Badly configured TrustedDirectory")));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        verify(handler, never()).handle(null, request);
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenRegRequestSigInvalid() throws Exception {
        // Given
        Map<String, Object> ssaClaimsMap = Map.of();
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);

        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);

        when(softwareStatementAssertionSignatureValidatorService.validateSoftwareStatementAssertionSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateRegistrationRequestJwtSignature(any(), any(), any()))
                .thenReturn(Promises.newExceptionPromise(
                        new DCRSignatureValidationException(ErrorCode.INVALID_CLIENT_METADATA, ERROR_DESCRIPTION)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).contains(ERROR_DESCRIPTION);
        verify(handler, never()).handle(null, request);
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenRTEValidatingRegRequestSig() throws Exception {
        // Given
        Map<String, Object> ssaClaimsMap = Map.of();
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);

        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);

        when(softwareStatementAssertionSignatureValidatorService.validateSoftwareStatementAssertionSignature(any(), any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateRegistrationRequestJwtSignature(any(), any(), any()))
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