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
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.request.DCRRequestValidationException.ErrorCode;
import com.forgerock.sapi.gateway.jwks.RestJwkSetServiceTest;
import com.forgerock.sapi.gateway.jwks.mocks.MockJwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryOpenBankingTest;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryServiceStatic;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

class RequestAndSsaSignatureValidationFilterTest {


    private Request request;
    private Handler handler = mock(Handler.class);
    private static RequestAndSsaSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier registrationObjectSupplier;
    private static RSASSASigner RSA_SIGNER;
    final private static JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);
    private MockJwkSetService jwkSetService;
    final private static String DIRECTORY_JWKS_URI = "https://keystore.openbankingtest.org.uk/keystore/openbanking.jwks";
    final private static String SOFTWARE_STATEMENT_JWKS_URI = "https://directory.softwareid.jwks_uri";

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
        registrationObjectSupplier = mock(RequestAndSsaSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier.class);
        handler = mock(Handler.class);
        Map<URL, JWKSet> jwkSetByUrl = new HashMap();
        jwkSetByUrl.put(new URL(DIRECTORY_JWKS_URI), createJwkSet());
        jwkSetByUrl.put(new URL(SOFTWARE_STATEMENT_JWKS_URI), createJwkSet());
        jwkSetService = new MockJwkSetService(jwkSetByUrl);
        this.request = new Request().setMethod("POST");
    }

    @AfterEach
    void tearDown() {
        reset(handler,  registrationObjectSupplier);
    }

    private TrustedDirectoryService getTrustedDirectory(boolean sapigDirectoryEnabled) {
        return new TrustedDirectoryServiceStatic(sapigDirectoryEnabled, "https://uri");
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
    void filter_success() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        Map<String, Object> ssaClaimsMap = Map.of("iss", "OpenBanking Ltd",
                TrustedDirectoryOpenBankingTest.softwareJwksUriClaimName, SOFTWARE_STATEMENT_JWKS_URI);
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        // When

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assert(response.getStatus()).isSuccessful();
        verify(handler, times(1)).handle(null, request);

    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenNoRegistrationRequestJwt() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                DCRRequestValidationException.ErrorCode.INVALID_CLIENT_METADATA.toString());
        assertThat(responseBody.get("error_description")).contains("Requests to registration endpoint must contain a " +
                "signed request jwt");
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenNoSoftwareStatement() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

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
    void filter_ResponseIsInvalidSoftwareStatementWhenSoftwareStatementHasNoIssuer() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        String encodedSsaJwtString = createEncodedJwtString(Map.of(), JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.INVALID_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("registration request's 'software_statement' jwt " +
                "must contain an issuer claim");
    }

    @Test
    void filter_ResponseIsUnapprovedSoftwareStatementWhenSoftwareStatementHasInvalidIssuer() throws ExecutionException,
            InterruptedException, TimeoutException, IOException {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);
        String encodedSsaJwtString = createEncodedJwtString(Map.of("iss", "InvalidIssuer"), JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.UNAPPROVED_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("SSA was not issued by a Trusted Directory");
    }

    @Test
    void filter_throwsInvalidSoftwareStatementWhenSoftwareStatementHasNoJwskUri() throws IOException, ExecutionException,
            InterruptedException, TimeoutException {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        String encodedSsaJwtString = createEncodedJwtString(Map.of("iss", "OpenBanking Ltd"),
                JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).contains(ErrorCode.INVALID_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("must contain a claim for the JWKS URI");
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenSoftwareStatementHasBadlyFormedJwskUri() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        Map<String, Object> ssaClaimsMap = Map.of("iss", "OpenBanking Ltd",
                TrustedDirectoryOpenBankingTest.softwareJwksUriClaimName, "not a url");
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.INVALID_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("must be a valid URL");
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenSoftwareStatementHasNonHttpsJwskUri() throws IOException,
            ExecutionException, InterruptedException, TimeoutException {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        Map<String, Object> ssaClaimsMap = Map.of("iss", "OpenBanking Ltd",
                TrustedDirectoryOpenBankingTest.softwareJwksUriClaimName, "http://google.co.uk");
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.INVALID_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("must contain an HTTPS URI");
    }
}