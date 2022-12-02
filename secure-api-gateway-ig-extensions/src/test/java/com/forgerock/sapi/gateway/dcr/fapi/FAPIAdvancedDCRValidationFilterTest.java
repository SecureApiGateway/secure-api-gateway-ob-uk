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
package com.forgerock.sapi.gateway.dcr.fapi;

import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.Handler;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.ValidationException;
import com.forgerock.sapi.gateway.dcr.ValidationException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.Validator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

class FAPIAdvancedDCRValidationFilterTest {

    private static final String CERT_HEADER_NAME = "x-cert";

    // Self signed test cert generated using openssl
    private static final String testCertPem = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDrTCCApWgAwIBAgIUJDeIu5DTsX49pI41PBFIXNeSOh8wDQYJKoZIhvcNAQEL\n" +
            "BQAwZjELMAkGA1UEBhMCVUsxEDAOBgNVBAgMB0JyaXN0b2wxEDAOBgNVBAcMB0Jy\n" +
            "aXN0b2wxEDAOBgNVBAoMB0ZSIFRlc3QxDTALBgNVBAsMBFRlc3QxEjAQBgNVBAMM\n" +
            "CXVuaXQudGVzdDAeFw0yMjEyMDExMzU3MDFaFw0zMjExMjgxMzU3MDFaMGYxCzAJ\n" +
            "BgNVBAYTAlVLMRAwDgYDVQQIDAdCcmlzdG9sMRAwDgYDVQQHDAdCcmlzdG9sMRAw\n" +
            "DgYDVQQKDAdGUiBUZXN0MQ0wCwYDVQQLDARUZXN0MRIwEAYDVQQDDAl1bml0LnRl\n" +
            "c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCi+Cg15QLYZ5wLEvPo\n" +
            "2Lsdny3AlHcPsPPYT4bmH0iIwOudZZEmwM44Kqh4yhwupu1WMa1fTkM+IjnrJ70o\n" +
            "HtwCUNA5yXfq+wjhlbl4+hdgautegtUqIqwzfMPtvDNXw5NRJXN6TwPzt4IYkj/P\n" +
            "Hm8myrOkg2ebUrazQPoHRVtCjc29vko5aYHecXTl787CXKWnwgV8f3hjAln8T+zw\n" +
            "szlAKjTxuF7MYSs9k2/AtLe998ZwZ4PYg8Qa/NTMAD/5Y2hWG95loe3kIh8YP+SJ\n" +
            "Ga/SXMSJulR3noPR++tmwBkDptHouKBs0uG3rdIHC2OnPFOk9akJTxCXsEivRfO2\n" +
            "pL/PAgMBAAGjUzBRMB0GA1UdDgQWBBS92afFuqfj7I7tnKZdn/xMbxZ7JzAfBgNV\n" +
            "HSMEGDAWgBS92afFuqfj7I7tnKZdn/xMbxZ7JzAPBgNVHRMBAf8EBTADAQH/MA0G\n" +
            "CSqGSIb3DQEBCwUAA4IBAQBjKNlzLesmGii3eXXxjfyz1zFMsHxWSPmHEjedtB43\n" +
            "zMs2/XWr0DFRh6B+pUg/c/J4t6rdTJb4HDUJRQwXF6jmSCAaPSF5hkKzI9RwPFC2\n" +
            "NvpcLiGbbCJdDQJ+n/0cJlofxMaMthb8/Dw2Dp/LRtMlju22abn/hwijxbBw0kj8\n" +
            "P34GPGP7j2ysoyNFARbbNWmn+Ym+A0LCM1/jvg92snniHLmeOZ4vdhOh8RwEl19u\n" +
            "6qpEGVrEFERZQ5TEnmp8/8mhs2RoWxavo9ZTia96p/A3PjI5n5663EQybMbFp0x5\n" +
            "ut3B6FJ1svFmln3Tq53bbd3iPXMwDZzqVubBkJnsmfib\n" +
            "-----END CERTIFICATE-----\n";

    private static RSASSASigner rsaSigner;

    private static Handler successHandler;
    private static Map<String, Object>  validRegistrationRequestClaims;

    private FAPIAdvancedDCRValidationFilter fapiValidationFilter;

    @BeforeAll
    public static void beforeAll() throws NoSuchAlgorithmException {
        rsaSigner = createRSASSASigner();
        successHandler = (ctx, req) -> Promises.newResultPromise(new Response(Status.OK));

        validRegistrationRequestClaims = new HashMap<>();
        validRegistrationRequestClaims.put("token_endpoint_auth_method", "private_key_jwt");
        validRegistrationRequestClaims.put("redirect_uris", List.of("https://google.co.uk"));
        validRegistrationRequestClaims.put("response_types", List.of("code id_token"));
        validRegistrationRequestClaims.put("token_endpoint_auth_signing_alg", "PS256");
        validRegistrationRequestClaims.put("id_token_signed_response_alg", "PS256");
        validRegistrationRequestClaims.put("request_object_signing_alg", "PS256");
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
    public void beforeEach() throws HeapException {
        fapiValidationFilter = createDefaultFapiFilter();
    }

    /**
     * Uses the Heaplet to create a FAPIAdvancedDCRValidationFilter with the default configuration.
     */
    private static FAPIAdvancedDCRValidationFilter createDefaultFapiFilter() throws HeapException {
        final HeapImpl emptyHeap = new HeapImpl(Name.of("testHeap"));
        final JsonValue filterConfig = json(object(field("certificateHeader", CERT_HEADER_NAME)));
        return (FAPIAdvancedDCRValidationFilter) new FAPIAdvancedDCRValidationFilter.Heaplet().create(Name.of("fapiTest"), filterConfig, emptyHeap);
    }

    private String createSignedJwt(Map<String, Object> claims) {
        return createSignedJwt(claims, JWSAlgorithm.PS256);
    }

    private String createSignedJwt(Map<String, Object> claims, JWSAlgorithm signingAlgo) {
        try {
            final SignedJWT signedJWT = new SignedJWT(new JWSHeader(signingAlgo), JWTClaimsSet.parse(claims));
            signedJWT.sign(rsaSigner);
            return signedJWT.serialize();
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private void validateErrorResponse(Response response, ErrorCode expectedErrorCode, String expectedErrorDescription) {
        assertEquals(Status.BAD_REQUEST, response.getStatus());
        assertEquals("application/json; charset=UTF-8", response.getHeaders().getFirst(ContentTypeHeader.class));
        try {
            final JsonValue errorResponseBody = (JsonValue) response.getEntity().getJson();
            assertEquals(expectedErrorCode.getCode(), errorResponseBody.get("error").asString());
            assertEquals(expectedErrorDescription, errorResponseBody.get("error_description").asString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private <T> void runValidationAndVerifyExceptionThrown(Validator<T> validator, T requestObject,
                                                           ErrorCode expectedErrorCode, String expectedErrorMessage) {
        final ValidationException validationException = Assertions.assertThrows(ValidationException.class,
                                                                                () -> validator.validate(requestObject));
        assertEquals(expectedErrorCode, validationException.getErrorCode(), "errorCode field");
        assertEquals(expectedErrorMessage, validationException.getErrorDescription(), "errorMessage field");
    }

    @Test
    void redirectUrisFieldMissing() {
        final JsonValue missingField = json(object(field("a", "b"), field("c", "d")));
        runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, missingField,
                ErrorCode.INVALID_REDIRECT_URI, "request object must contain redirect_uris field");
    }

    @Test
    void redirectUrisArrayEmpty() {
        final JsonValue emptyArray = json(object(field("a", "b"), field("c", "d"),
                field("redirect_uris", array())));
        runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, emptyArray,
                ErrorCode.INVALID_REDIRECT_URI, "redirect_uris array must not be empty");
    }

    @Test
    void redirectUrisNonHttpsUri() {
        final JsonValue nonHttpsRedirect = json(object(field("a", "b"), field("c", "d"),
                field("redirect_uris", array("https://www.google.com", "http://www.google.co.uk"))));
        runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, nonHttpsRedirect,
                ErrorCode.INVALID_REDIRECT_URI, "redirect_uris must use https scheme");
    }

    @Test
    void validRedirectUris() {
        final JsonValue validRedirect = json(object(field("a", "b"), field("c", "d"),
                field("redirect_uris", array("https://www.google.com", "https://www.google.co.uk"))));
        fapiValidationFilter.validateRedirectUris(validRedirect);
    }

    @Test
    void tokenEndpointAuthMethodFieldMissing() {
        final JsonValue missingField = json(object(field("a", "b"), field("c", "d")));
        runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateTokenEndpointAuthMethods, missingField,
                ErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: token_endpoint_auth_method");
    }

    @Test
    void tokenEndpointAuthMethodValueNotSupported() {
        final String[] invalidAuthMethods = new String[]{"", "none", "client_secret"};
        for (String invalidAuthMethod : invalidAuthMethods) {
            final JsonValue invalidAuthMethodJson = json(object(field("a", "b"), field("c", "d"), field("token_endpoint_auth_method", invalidAuthMethod)));
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateTokenEndpointAuthMethods, invalidAuthMethodJson,
                    ErrorCode.INVALID_CLIENT_METADATA, "token_endpoint_auth_method not supported, must be one of: [private_key_jwt, self_signed_tls_client_auth, tls_client_auth]");
        }
    }

    @Test
    void tokenEndpointAuthMethodValid() {
        final String[] validMethods = new String[]{"private_key_jwt", "self_signed_tls_client_auth", "tls_client_auth"};
        for (String validAuthMethod : validMethods) {
            final JsonValue validAuthMethodJson = json(object(field("a", "b"), field("c", "d"), field("token_endpoint_auth_method", validAuthMethod)));
            fapiValidationFilter.validateTokenEndpointAuthMethods(validAuthMethodJson);
        }
    }

    @Test
    void signingAlgorithmFieldsMissing() {
        // All of these fields must be supplied
        final List<String> signingAlgoFields = List.of("token_endpoint_auth_signing_alg", "id_token_signed_response_alg",
                                                       "request_object_signing_alg");

        // Test submitting requests which each omit one of the fields in turn
        for (String fieldToOmit : signingAlgoFields) {
            final JsonValue registrationRequest = json(object());
            signingAlgoFields.stream().filter(field -> !field.equals(fieldToOmit)).forEach(field -> registrationRequest.add(field, "PS256"));
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateSigningAlgorithmUsed, registrationRequest,
                    ErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: " + fieldToOmit);
        }
    }

    @Test
    void signingAlgorithmFieldsUnsupportedAlgo() {
        final List<String> signingAlgoFields = List.of("token_endpoint_auth_signing_alg", "id_token_signed_response_alg",
                                                       "request_object_signing_alg");

        // Test submitting requests which each set one of the fields to an invalid algorithm in turn
        for (String invalidAlgoField : signingAlgoFields) {
            final JsonValue registrationRequest = json(object());
            signingAlgoFields.stream().filter(field -> !field.equals(invalidAlgoField)).forEach(field -> registrationRequest.add(field, "PS256"));
            registrationRequest.add(invalidAlgoField, "RS256");
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateSigningAlgorithmUsed, registrationRequest,
                    ErrorCode.INVALID_CLIENT_METADATA, "request object field: " + invalidAlgoField + ", must be one of: [ES256, PS256]");
        }
    }

    @Test
    void signingAlgorithmFieldsValid() {
        fapiValidationFilter.validateSigningAlgorithmUsed(json(object(field("token_endpoint_auth_signing_alg", "PS256"),
                                                                      field("id_token_signed_response_alg", "PS256"),
                                                                      field("request_object_signing_alg", "PS256"))));
    }

    @Test
    void responseTypeFieldMissing() {
        runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateResponseTypes, json(object(field("blah", "blah"))),
                ErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: response_types");
    }

    @Test
    void responseTypesInvalid() {
        runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateResponseTypes, json(object(field("response_types", array("blah")))),
                ErrorCode.INVALID_CLIENT_METADATA, "response_types not supported, must be one of: [[code], [code id_token]]");
    }

    @Test
    void responseTypesCodeValid() {
        fapiValidationFilter.validateResponseTypes(json(object(field("response_types", array("code")), field("response_mode", "jwt"))));
    }

    @Test
    void responseTypesCodeMissingResponseMode() {
        runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateResponseTypes, json(object(field("response_types", array("code")))),
                ErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: response_mode when response_types is: [code]");
    }

    @Test
    void responseTypesCodeInvalidResponseMode() {
        runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateResponseTypes, json(object(field("response_types", array("code")),
                                                                                                       field("response_mode", "blah"))),
                ErrorCode.INVALID_CLIENT_METADATA, "response_mode not supported, must be one of: [jwt]");
    }

    @Test
    void responseTypesCodeIdTokenValid() {
        fapiValidationFilter.validateResponseTypes(json(object(field("response_types", array("code id_token")))));
    }

    @Test
    void validRequest() throws InterruptedException, ExecutionException, TimeoutException, IOException {
        final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
        final Request request = new Request();
        request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(testCertPem, StandardCharsets.UTF_8)));

        final String signedJwt = createSignedJwt(validRegistrationRequestClaims);
        request.getEntity().setString(signedJwt);

        final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        if (!response.getStatus().isSuccessful()) {
            fail("Expected a successful response instead got: " + response.getStatus() + ", entity: " + response.getEntity().getJson());
        }
    }

    @Test
    void invalidRequestFailsFieldLevelValidation() throws InterruptedException, ExecutionException, TimeoutException, IOException {
        final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
        final Request request = new Request();
        request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(testCertPem, StandardCharsets.UTF_8)));

        final Map<String, Object> invalidRegistrationRequest = new HashMap<>(validRegistrationRequestClaims);
        invalidRegistrationRequest.put("token_endpoint_auth_method", "blah"); // invalidate one of the fields
        final String signedJwt = createSignedJwt(invalidRegistrationRequest);
        request.getEntity().setString(signedJwt);

        final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
        validateErrorResponse(response, ErrorCode.INVALID_CLIENT_METADATA,
                "token_endpoint_auth_method not supported, must be one of: " +
                        "[private_key_jwt, self_signed_tls_client_auth, tls_client_auth]");
    }


    @Test
    void invalidRequestMissingCert() throws Exception {
        final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
        final Request request = new Request();

        final String signedJwt = createSignedJwt(validRegistrationRequestClaims);
        request.getEntity().setString(signedJwt);

        final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
        validateErrorResponse(response, ErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate must be supplied");
    }

    @Test
    void invalidRequestInvalidCert() throws Exception {
        final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
        final Request request = new Request();
        request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode("this is an invalid cert......", StandardCharsets.UTF_8)));

        final String signedJwt = createSignedJwt(validRegistrationRequestClaims);
        request.getEntity().setString(signedJwt);

        final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
        validateErrorResponse(response, ErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate PEM supplied is invalid");
    }

    @Test
    void invalidRequestInvalidJwt() throws Exception {
        final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
        final Request request = new Request();
        request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(testCertPem, StandardCharsets.UTF_8)));

        request.getEntity().setString("plain text instead of a JWT");

        final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
        validateErrorResponse(response, ErrorCode.INVALID_CLIENT_METADATA, "registration request entity is missing or malformed");
    }

    @Test
    void invalidRequestJwtSignedWithUnsupportedAlgo() throws Exception {
        final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
        final Request request = new Request();
        request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(testCertPem, StandardCharsets.UTF_8)));

        // RS256 JWT signing algorithm not supported
        final String signedJwt = createSignedJwt(validRegistrationRequestClaims, JWSAlgorithm.RS256);
        request.getEntity().setString(signedJwt);

        final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
        validateErrorResponse(response, ErrorCode.INVALID_CLIENT_METADATA, "DCR request JWT signed must be signed with one of: [ES256, PS256]");
    }
}