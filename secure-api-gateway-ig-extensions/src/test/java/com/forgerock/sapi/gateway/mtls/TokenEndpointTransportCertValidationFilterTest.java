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
package com.forgerock.sapi.gateway.mtls;

import static com.forgerock.sapi.gateway.mtls.TokenEndpointTransportCertValidationFilter.DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.forgerock.http.handler.Handlers;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.idm.ApiClientService;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.jwks.ApiClientJwkSetService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryOpenBankingTest;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.TestHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;
import com.nimbusds.jose.JWSAlgorithm;

class TokenEndpointTransportCertValidationFilterTest {

    @Nested
    class TransportCertValidationTests {

        private TokenEndpointTransportCertValidationFilter transportCertValidationFilter;

        private ApiClientService mockApiClientService;

        private TrustedDirectoryService mockTrustedDirectoryService;

        private ApiClientJwkSetService mockApiClientJwkSetService;

        private CertificateResolver mockCertificateResolver;

        private TransportCertValidator mockTransportCertValidator;


        @BeforeEach
        public void createValidFilter() {
            mockApiClientService = mock(ApiClientService.class);
            mockTrustedDirectoryService = mock(TrustedDirectoryService.class);
            mockApiClientJwkSetService = mock(ApiClientJwkSetService.class);

            // Default resolver behavior is to throw an exception
            mockCertificateResolver = mock(CertificateResolver.class, invocationOnMock -> {
                throw new CertificateException("invalid cert");
            });
            mockTransportCertValidator = mock(TransportCertValidator.class);

            transportCertValidationFilter = new TokenEndpointTransportCertValidationFilter(mockApiClientService, mockTrustedDirectoryService,
                    mockApiClientJwkSetService, mockCertificateResolver, mockTransportCertValidator, DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM);
        }

        @Test
        void failsWhenCertNotFound() throws Exception {
            final TestSuccessResponseHandler handler = new TestSuccessResponseHandler();
            final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(new RootContext("root"), new Request(), handler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);

            validateResponseIsBadRequest(response, "invalid cert");
            assertFalse(handler.hasBeenInteractedWith(), "next handler must not be reached");
        }

        @Test
        void errorResponseFromNextHandlerIsPassedOn() throws Exception {
            // next handler in chain returns forbidden response
            final TestHandler nextHandler = new TestHandler(Handlers.forbiddenHandler());
            doReturn(mock(X509Certificate.class)).when(mockCertificateResolver).resolveCertificate(any(), any());
            final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(new RootContext("root"), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.FORBIDDEN, response.getStatus());
        }

        @Test
        void failsWhenResponseJsonIOException() throws Exception {
            final TestHandler nextHandler = new TestHandler((ctxt, request) -> {
                final Response response = new Response(Status.OK);
                response.close(); // Close the response stream, causes end-of-input IOException
                return Promises.newResultPromise(response);
            });

            doReturn(mock(X509Certificate.class)).when(mockCertificateResolver).resolveCertificate(any(), any());

            final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(new RootContext("root"), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void failsWhenClientIdNotInResponse() throws Exception {
            final TestHandler nextHandler = new TestHandler((ctxt, request) -> {
                final Response response = new Response(Status.OK);
                // AM response missing access_token field
                final JsonValue jsonResponseMissingAccessTokenField = json(object(field("refresh_token", "addff")));
                response.setEntity(jsonResponseMissingAccessTokenField);
                return Promises.newResultPromise(response);
            });

            doReturn(mock(X509Certificate.class)).when(mockCertificateResolver).resolveCertificate(any(), any());

            final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(new RootContext("root"), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void failsWhenApiClientCouldNotBeFound() throws Exception {
            final String testClientId = "client999";
            final TestHandler nextHandler = new TestHandler((ctxt, request) -> {
                final Response response = new Response(Status.OK);
                final JsonValue jsonResponseMissingAccessTokenField = json(object(field("access_token", createAccessToken(Map.of(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM, testClientId)))));
                response.setEntity(jsonResponseMissingAccessTokenField);
                return Promises.newResultPromise(response);
            });

            doReturn(mock(X509Certificate.class)).when(mockCertificateResolver).resolveCertificate(any(), any());
            doReturn(Promises.newExceptionPromise(new Exception("boom"))).when(mockApiClientService).getApiClient(eq(testClientId));

            final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(new RootContext("root"), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void failsWhenTrustedDirectoryConfigCouldNotBeFound() throws Exception {
            final String testClientId = "client999";
            final ApiClient apiClient = new ApiClient();
            apiClient.setOauth2ClientId(testClientId);
            final URI jwksUri = new URI("http://localhost/jwks");
            apiClient.setJwksUri(jwksUri);

            final TestHandler nextHandler = new TestHandler((ctxt, request) -> {
                final Response response = new Response(Status.OK);
                final JsonValue jsonResponseMissingAccessTokenField = json(object(field("access_token", createAccessToken(Map.of(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM, testClientId)))));
                response.setEntity(jsonResponseMissingAccessTokenField);
                return Promises.newResultPromise(response);
            });

            doReturn(mock(X509Certificate.class)).when(mockCertificateResolver).resolveCertificate(any(), any());
            doReturn(Promises.newResultPromise(apiClient)).when(mockApiClientService).getApiClient(eq(testClientId));

            final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(new RootContext("root"), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void failsWhenApiClientJwksCouldNotBeFound() throws Exception {
            final String testClientId = "client999";
            final ApiClient apiClient = new ApiClient();
            apiClient.setOauth2ClientId(testClientId);
            final URI jwksUri = new URI("http://localhost/jwks");
            apiClient.setJwksUri(jwksUri);

            final TrustedDirectoryOpenBankingTest trustedDirectory = new TrustedDirectoryOpenBankingTest();

            final TestHandler nextHandler = new TestHandler((ctxt, request) -> {
                final Response response = new Response(Status.OK);
                final JsonValue jsonResponseMissingAccessTokenField = json(object(field("access_token", createAccessToken(Map.of(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM, testClientId)))));
                response.setEntity(jsonResponseMissingAccessTokenField);
                return Promises.newResultPromise(response);
            });

            final X509Certificate clientCert = mock(X509Certificate.class);
            doReturn(clientCert).when(mockCertificateResolver).resolveCertificate(any(), any());
            doReturn(Promises.newResultPromise(apiClient)).when(mockApiClientService).getApiClient(eq(testClientId));

            doReturn(trustedDirectory).when(mockTrustedDirectoryService).getTrustedDirectoryConfiguration(eq(apiClient));
            doReturn(Promises.newExceptionPromise(new FailedToLoadJWKException("boom"))).when(mockApiClientJwkSetService).getJwkSet(eq(apiClient), eq(trustedDirectory));

            final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(new RootContext("root"), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void failsWhenTransportCertValidationFails()  throws Exception {
            final String testClientId = "client999";
            final ApiClient apiClient = new ApiClient();
            apiClient.setOauth2ClientId(testClientId);
            final URI jwksUri = new URI("http://localhost/jwks");
            apiClient.setJwksUri(jwksUri);

            final TrustedDirectoryOpenBankingTest trustedDirectory = new TrustedDirectoryOpenBankingTest();

            final TestHandler nextHandler = new TestHandler((ctxt, request) -> {
                final Response response = new Response(Status.OK);
                final JsonValue jsonResponseMissingAccessTokenField = json(object(field("access_token", createAccessToken(Map.of(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM, testClientId)))));
                response.setEntity(jsonResponseMissingAccessTokenField);
                return Promises.newResultPromise(response);
            });

            final X509Certificate clientCert = mock(X509Certificate.class);
            doReturn(clientCert).when(mockCertificateResolver).resolveCertificate(any(), any());
            doReturn(Promises.newResultPromise(apiClient)).when(mockApiClientService).getApiClient(eq(testClientId));

            doReturn(trustedDirectory).when(mockTrustedDirectoryService).getTrustedDirectoryConfiguration(eq(apiClient));


            final JWKSet clientJwks = new JWKSet();
            doReturn(Promises.newResultPromise(clientJwks)).when(mockApiClientJwkSetService).getJwkSet(eq(apiClient), eq(trustedDirectory));
            doThrow(new CertificateException("Cert has expired")).when(mockTransportCertValidator).validate(eq(clientCert), eq(clientJwks));
            final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(new RootContext("root"), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            validateResponseIsBadRequest(response, "Cert has expired");
        }

        @Test
        void succeedsWhenCertIsValid() throws Exception {
            final String testClientId = "client999";
            final ApiClient apiClient = new ApiClient();
            apiClient.setOauth2ClientId(testClientId);
            final URI jwksUri = new URI("http://localhost/jwks");
            apiClient.setJwksUri(jwksUri);

            final TrustedDirectoryOpenBankingTest trustedDirectory = new TrustedDirectoryOpenBankingTest();

            final TestHandler nextHandler = new TestHandler((ctxt, request) -> {
                final Response response = new Response(Status.OK);
                final JsonValue jsonResponseMissingAccessTokenField = json(object(field("access_token", createAccessToken(Map.of(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM, testClientId)))));
                response.setEntity(jsonResponseMissingAccessTokenField);
                return Promises.newResultPromise(response);
            });

            final X509Certificate clientCert = mock(X509Certificate.class);
            doReturn(clientCert).when(mockCertificateResolver).resolveCertificate(any(), any());
            doReturn(Promises.newResultPromise(apiClient)).when(mockApiClientService).getApiClient(eq(testClientId));

            doReturn(trustedDirectory).when(mockTrustedDirectoryService).getTrustedDirectoryConfiguration(eq(apiClient));


            final JWKSet clientJwks = new JWKSet();
            doReturn(Promises.newResultPromise(clientJwks)).when(mockApiClientJwkSetService).getJwkSet(eq(apiClient), eq(trustedDirectory));
            final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(new RootContext("root"), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);

            assertEquals(Status.OK, response.getStatus());
            assertTrue(nextHandler.hasBeenInteractedWith());
        }
        private void validateResponseIsBadRequest(Response response, String expectedErrorMsg) {
            assertEquals(Status.BAD_REQUEST, response.getStatus());
            try {
                final Object responseJson = response.getEntity().getJson();
                assertEquals(expectedErrorMsg, json(responseJson).get("error_description").asString());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Nested
    class ClientIdParsingTests {

        @Test
        void testParseClientIdMissingAccessToken() {
            final TokenEndpointTransportCertValidationFilter filter = createFilter();

            final JsonValue jsonResponseMissingAccessTokenField = json(object(field("someOtherKey", "someOtherValue")));
            final IllegalStateException illegalStateException = assertThrows(IllegalStateException.class, () -> filter.getClientId(jsonResponseMissingAccessTokenField));
            assertEquals("Failed to get client_id: access_token is missing", illegalStateException.getMessage());
        }

        @Test
        void testParseClientIdAccessTokenNotJwt() {
            final TokenEndpointTransportCertValidationFilter filter = createFilter();

            final JsonValue accessTokenInvalidJwt = json(object(field("access_token", "sdfsfsdfsdfsf")));
            final InvalidJwtException invalidJwtException = assertThrows(InvalidJwtException.class, () -> filter.getClientId(accessTokenInvalidJwt));
            assertEquals("not right number of dots, 1", invalidJwtException.getMessage());
        }

        @Test
        void testParseClientIdAccessTokenMissingClientIdClaim() {
            final TokenEndpointTransportCertValidationFilter filter = createFilter();

            final JsonValue accessTokenMissingClientIdClaim = json(object(field("access_token", createAccessToken(Map.of("claim1", "value1")))));
            final IllegalStateException illegalStateException = assertThrows(IllegalStateException.class, () -> filter.getClientId(accessTokenMissingClientIdClaim));
            assertEquals("Failed to get client_id: access_token claims missing required '" + DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM + "' claim", illegalStateException.getMessage());
        }

        @Test
        void testParseClientIdSuccessfully() {
            final TokenEndpointTransportCertValidationFilter filter = createFilter();

            final String clientId = "clientId123";
            final JsonValue accessTokenClientIdNotString = json(object(field("access_token", createAccessToken(Map.of(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM, clientId)))));
            assertEquals(clientId, filter.getClientId(accessTokenClientIdNotString));
        }

        private TokenEndpointTransportCertValidationFilter createFilter() {
            return new TokenEndpointTransportCertValidationFilter(mock(ApiClientService.class), mock(TrustedDirectoryService.class),
                    mock(ApiClientJwkSetService.class), mock(CertificateResolver.class), mock(TransportCertValidator.class),
                    DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM);
        }


    }

    private String createAccessToken(Map<String, Object> claims) {
        return CryptoUtils.createEncodedJwtString(claims, JWSAlgorithm.PS256);
    }
}