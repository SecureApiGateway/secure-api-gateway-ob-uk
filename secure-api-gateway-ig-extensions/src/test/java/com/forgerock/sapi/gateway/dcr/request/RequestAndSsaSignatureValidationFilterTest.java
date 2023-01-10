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

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.ValidationException;
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

    private static Map<String, Object> VALID_REG_REQUEST_CLAIMS;

    private Request request = new Request().setMethod("POST");
    private static TransactionIdContext txIdContext;
    private Handler clientHandler = mock(Handler.class);
    private Handler handler = mock(Handler.class);
    private static RequestAndSsaSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier registrationObjectSupplier;
    private static RSASSASigner RSA_SIGNER;
    private static JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);

    private MockJwkSetService jwkSetService;

    private static String DIRECTORY_JWKS_URI = "https://keystore.openbankingtest.org.uk/keystore/openbanking.jwks";
    private static String SOFTWARE_STATEMENT_JWKS_URI = "https://directory.softwareid.jwks_uri";


    @BeforeAll
    public static void beforeAll() throws NoSuchAlgorithmException {
        TransactionId txId = new TransactionId();
        Context context = mock(Context.class);
        txIdContext = new TransactionIdContext(context, txId);
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
        JWKSet jwkSet = createJwkSet();
        Map<URL, JWKSet> jwkSetByUrl = new HashMap();
        jwkSetByUrl.put(new URL(DIRECTORY_JWKS_URI), createJwkSet());
        jwkSetByUrl.put(new URL(SOFTWARE_STATEMENT_JWKS_URI), createJwkSet());
        jwkSetService = new MockJwkSetService(jwkSetByUrl);
    }

    @AfterEach
    void tearDown() {
        reset(handler, clientHandler, registrationObjectSupplier);
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
    void filter_success() {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(clientHandler,
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
        filter.filter(null, request, handler).thenOnResult(res -> {
            verify(handler, times(1)).handle(null, request);
        });
    }

    @Test
    void filter_throwsInvalidClientMetadataWhenNoRegistrationRequestJwt() {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(clientHandler,
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        // When
        ValidationException exception = catchThrowableOfType(() ->
                filter.filter(null, request, handler), ValidationException.class);

        // Then
        verify(handler, never()).handle(null, request);
        assertThat(exception.getErrorCode()).isEqualTo(ValidationException.ErrorCode.INVALID_CLIENT_METADATA);
    }

    @Test
    void filter_throwsInvalidClientMetadataWhenNoSoftwareStatement() {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(clientHandler,
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        SignedJwt signedJwt = createSignedJwt(Map.of(), JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        ValidationException exception = catchThrowableOfType(() ->
                filter.filter(null, request, handler), ValidationException.class);

        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ValidationException.ErrorCode.INVALID_CLIENT_METADATA);
    }

    @Test
    void filter_throwsInvalidClientMetadataWhenSoftwareStatementHasNoIssuer() {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(clientHandler,
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        String encodedSsaJwtString = createEncodedJwtString(Map.of(), JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        ValidationException exception = catchThrowableOfType(() ->
                filter.filter(null, request, handler), ValidationException.class);
        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void filter_throwsInvalidClientMetadataWhenSoftwareStatementInvalidIssuer() {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(clientHandler,
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);
        String encodedSsaJwtString = createEncodedJwtString(Map.of("iss", "InvalidIssuer"), JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        ValidationException exception = catchThrowableOfType(() ->
                filter.filter(null, request, handler), ValidationException.class);
        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ValidationException.ErrorCode.UNAPPROVED_SOFTWARE_STATEMENT);
    }

    @Test
    void filter_throwsInvalidClientMetadataWhenSoftwareStatementHasNoJwskUri() {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(clientHandler,
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        String encodedSsaJwtString = createEncodedJwtString(Map.of("iss", "OpenBanking Ltd"), JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        ValidationException exception = catchThrowableOfType(() ->
                filter.filter(null, request, handler), ValidationException.class);
        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void filter_throwsInvalidClientMetadataWhenSoftwareStatementHasBadlyFormedJwskUri() throws MalformedURLException {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(clientHandler,
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        Map<String, Object> ssaClaimsMap = Map.of("iss", "OpenBanking Ltd",
                TrustedDirectoryOpenBankingTest.softwareJwksUriClaimName, "not a url");
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);


        // When
        ValidationException exception = catchThrowableOfType(() ->
                filter.filter(null, request, handler), ValidationException.class);
        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT);
        assertThat(exception.getErrorDescription()).contains("must be a valid URL");
    }

    @Test
    void filter_throwsInvalidClientMetadataWhenSoftwareStatementHasNonHttpsJwskUri() {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(clientHandler,
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        Map<String, Object> ssaClaimsMap = Map.of("iss", "OpenBanking Ltd",
                TrustedDirectoryOpenBankingTest.softwareJwksUriClaimName, "http://google.co.uk");
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        ValidationException exception = catchThrowableOfType(() ->
                filter.filter(null, request, handler), ValidationException.class);
        // Then
        assertThat(exception.getErrorCode()).isEqualTo(ValidationException.ErrorCode.INVALID_SOFTWARE_STATEMENT);
        assertThat(exception.getErrorDescription()).contains("must contain an HTTPS URI");
    }
}