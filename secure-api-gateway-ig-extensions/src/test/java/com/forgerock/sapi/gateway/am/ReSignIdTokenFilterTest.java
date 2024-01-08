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
package com.forgerock.sapi.gateway.am;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.MutableUri;
import org.forgerock.http.header.LocationHeader;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.AccessTokenEndpointIdTokenAccessorLocator;
import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.AuthorizeEndpointIdTokenAccessorLocator;
import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.Heaplet;
import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.IdTokenAccessorLocator;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestHandler;
import com.nimbusds.jose.crypto.RSASSASigner;

class ReSignIdTokenFilterTest {

    // Filter does not touch this value so does not need to be a valid JWT
    private static final String ACCESS_TOKEN_VALUE = "access-token-123";
    private static final String SCOPE_VALUE = "openid payments";
    private static final String TOKEN_TYPE_VALUE = "Bearer";
    private static final int EXPIRES_IN_VALUE = 359999;
    private static final String ACCESS_TOKEN = "access_token";
    private static final String SCOPE = "scope";
    private static final String ID_TOKEN = "id_token";
    private static final String TOKEN_TYPE = "token_type";
    private static final String EXPIRES_IN = "expires_in";
    private static final String REDIRECT_URI = "https://acme-fintech/callback";
    private static final String AUTHORISATION_CODE_PARAM = "code";
    private static final String AUTHORISATION_CODE_VALUE = "fsfgfgftwtqrtwq34";

    private final JwtReSignerTestResourceManager jwtReSignerTestResourceManager;
    private final JwtReSigner jwtReSigner;

    public ReSignIdTokenFilterTest() {
        jwtReSignerTestResourceManager = new JwtReSignerTestResourceManager();
        jwtReSigner = jwtReSignerTestResourceManager.getJwtReSigner();
    }

    private static Response buildAccessTokenEndpointResponse(String idToken) {
        return new Response(Status.OK).setEntity(json(object(
                field(ACCESS_TOKEN, ACCESS_TOKEN_VALUE),
                field(SCOPE, SCOPE_VALUE),
                field(ID_TOKEN, idToken),
                field(TOKEN_TYPE, TOKEN_TYPE_VALUE),
                field(EXPIRES_IN, EXPIRES_IN_VALUE)

        )));
    }

    private static Response buildAuthoriseEndpointFragmentResponse(String idToken) {
        return buildAuthoriseEndpointResponse(true, idToken);
    }

    private static Response buildAuthoriseEndpointQueryResponse(String idToken) {
        return buildAuthoriseEndpointResponse(false, idToken);
    }

    private static Response buildAuthoriseEndpointResponse(boolean fragment, String idToken) {
        final String locationUri = REDIRECT_URI + (fragment ? "#" : "?")
                + AUTHORISATION_CODE_PARAM + "=" + AUTHORISATION_CODE_VALUE + "&" + ID_TOKEN + "=" + idToken;

        return new Response(Status.OK).addHeaders(new LocationHeader(locationUri));
    }

    private ReSignIdTokenFilter createFilter(IdTokenAccessorLocator idTokenAccessorLocator) {
        return new ReSignIdTokenFilter(jwtReSigner, idTokenAccessorLocator);
    }

    @Test
    void testAccessTokenEndpointIdTokenIsReSigned() {
        testAccessTokenEndpointIdTokenIsReSigned(createFilter(new AccessTokenEndpointIdTokenAccessorLocator()));
    }

    private void testAccessTokenEndpointIdTokenIsReSigned(ReSignIdTokenFilter reSignIdTokenFilter) {
        final String expectedJti = UUID.randomUUID().toString();
        final TestHandler responseHandler = new FixedResponseHandler(buildAccessTokenEndpointResponse(jwtReSignerTestResourceManager.createAmSignedIdToken(expectedJti)));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);

        validateSuccessResponseJwt(response, expectedJti);
    }

    @Test
    void testAuthoriseEndpointFragmentIdTokenIsReSigned() {
        testAuthoriseEndpointFragmentIdTokenIsReSigned(createFilter(new AuthorizeEndpointIdTokenAccessorLocator()));
    }

    private void testAuthoriseEndpointFragmentIdTokenIsReSigned(ReSignIdTokenFilter reSignIdTokenFilter) {
        final String expectedJti = UUID.randomUUID().toString();
        final TestHandler responseHandler = new FixedResponseHandler(buildAuthoriseEndpointFragmentResponse(jwtReSignerTestResourceManager.createAmSignedIdToken(expectedJti)));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);

        validateSuccessAuthoriseFragmentResponse(response, expectedJti);
    }

    @Test
    void testAuthoriseEndpointQueryIdTokenIsReSigned() {
        testAuthoriseEndpointQueryIdTokenIsReSigned(createFilter(new AuthorizeEndpointIdTokenAccessorLocator()));
    }

    private void testAuthoriseEndpointQueryIdTokenIsReSigned(ReSignIdTokenFilter reSignIdTokenFilter) {
        final String expectedJti = UUID.randomUUID().toString();
        final TestHandler responseHandler = new FixedResponseHandler(buildAuthoriseEndpointQueryResponse(jwtReSignerTestResourceManager.createAmSignedIdToken(expectedJti)));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);

        validateSuccessAuthoriseQueryResponse(response, expectedJti);
    }

    @Test
    void testAmErrorResponsesArePassedThrough()  {
        final ReSignIdTokenFilter reSignIdTokenFilter = createFilter(new AccessTokenEndpointIdTokenAccessorLocator());
        final TestHandler responseHandler = new FixedResponseHandler(new Response(Status.BAD_REQUEST));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);
        assertEquals(Status.BAD_REQUEST, response.getStatus());
    }

    @Test
    void testAccessTokenResponsesWithNoIdTokenArePassedThrough() throws IOException {
        final ReSignIdTokenFilter reSignIdTokenFilter = createFilter(new AccessTokenEndpointIdTokenAccessorLocator());
        final TestHandler responseHandler = new FixedResponseHandler(buildAccessTokenEndpointResponse(null));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);

        assertEquals(Status.OK, response.getStatus());
        validateResponseJwtNonIdTokenFields(response);
        assertTrue(json(response.getEntity().getJson()).get("id_token").isNull());
    }



    @Test
    void testAccessTokenResponseNotJsonRaisesError() {
        final ReSignIdTokenFilter reSignIdTokenFilter = createFilter(new AccessTokenEndpointIdTokenAccessorLocator());

        // Form response instead of json
        final TestHandler responseHandler = new FixedResponseHandler(new Response(Status.OK).setEntity(new Form().fromQueryString("key=value")));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Test
    void testIdTokensNotSignedCorrectlyRaisesError() {
        final ReSignIdTokenFilter reSignIdTokenFilter = createFilter(new AccessTokenEndpointIdTokenAccessorLocator());
        final String expectedJti = UUID.randomUUID().toString();

        final RSASSASigner signerWithUnknownKey = new RSASSASigner(CryptoUtils.generateRsaKeyPair().getPrivate());
        final TestHandler responseHandler = new FixedResponseHandler(buildAccessTokenEndpointResponse(
                jwtReSignerTestResourceManager.createSignedIdToken(signerWithUnknownKey, "kid-123", expectedJti)));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Nested
    class HeapletTests {

        @Test
        void testConstructAccessTokenEndpointFilter() throws HeapException {
            final Name test = Name.of("test");
            final ReSignIdTokenFilter filter = (ReSignIdTokenFilter) new Heaplet().create(test,
                    createJsonConfig("access_token"), createHeap());

            testAccessTokenEndpointIdTokenIsReSigned(filter);
        }

        @Test
        void testConstructAuthoriseEndpointFilter() throws HeapException {
            final Name test = Name.of("test");

            final ReSignIdTokenFilter filter = (ReSignIdTokenFilter) new Heaplet().create(test,
                    createJsonConfig("authorize"), createHeap());

            testAuthoriseEndpointFragmentIdTokenIsReSigned(filter);
            testAuthoriseEndpointQueryIdTokenIsReSigned(filter);
        }

        @Test
        void failToConstructForUnsupportedEndpointType() {
            final Name test = Name.of("test");

            final NullPointerException exception = assertThrows(NullPointerException.class, () -> new Heaplet().create(test,
                    createJsonConfig("blah"), createHeap()));
            assertEquals("Unsupported endpointType: blah, specify one of: [access_token, authorize]", exception.getMessage());
        }

        private HeapImpl createHeap() {
            final HeapImpl heap = new HeapImpl(Name.of("test"));
            heap.put("jwtReSigner", jwtReSigner);
            return heap;
        }

        private JsonValue createJsonConfig(String endpointType) {
            return json(object(field("jwtReSigner", "jwtReSigner"),
                               field("endpointType", endpointType)));
        }

    }

    private static Response invokeFilter(ReSignIdTokenFilter reSignIdTokenFilter, TestHandler responseHandler)  {
        final Context context = new AttributesContext(new RootContext());
        final Promise<Response, NeverThrowsException> responsePromise = reSignIdTokenFilter.filter(context, new Request(), responseHandler);
        try {
            return responsePromise.get(1, TimeUnit.SECONDS);
        } catch (ExecutionException | TimeoutException | InterruptedException e) {
            throw new RuntimeException(e);
        } finally {
            assertTrue(responseHandler.hasBeenInteractedWith());
        }
    }

    private void validateSuccessResponseJwt(Response response, String expectedIdTokenJti) {
        assertEquals(Status.OK, response.getStatus());
        try {
            final JsonValue json = validateResponseJwtNonIdTokenFields(response);

            final String idToken = json.get(ID_TOKEN).asString();
            jwtReSignerTestResourceManager.validateIdTokenHasBeenReSigned(expectedIdTokenJti, idToken);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private static JsonValue validateResponseJwtNonIdTokenFields(Response response) throws IOException {
        final JsonValue json = json(response.getEntity().getJson());
        assertTrue(json.isMap());
        // Valid non id_token fields in AM response are untouched by the filter
        assertEquals(ACCESS_TOKEN_VALUE, json.get(ACCESS_TOKEN).asString());
        assertEquals(SCOPE_VALUE, json.get(SCOPE).asString());
        assertEquals(TOKEN_TYPE_VALUE, json.get(TOKEN_TYPE).asString());
        assertEquals(EXPIRES_IN_VALUE, json.get(EXPIRES_IN).asInteger());
        return json;
    }

    private void validateSuccessAuthoriseFragmentResponse(Response response, String expectedIdTokenJti) {
        assertEquals(Status.OK, response.getStatus());
        final MutableUri locationUri = getLocationUri(response);
        try {
            final Optional<String> idToken = new Form().fromQueryString(locationUri.getFragment()).get(ID_TOKEN).stream().findFirst();
            assertTrue(idToken.isPresent());
            jwtReSignerTestResourceManager.validateIdTokenHasBeenReSigned(expectedIdTokenJti, idToken.get());
        } catch (ParseException ex) {
            throw new RuntimeException(ex);
        }
    }

    private void validateSuccessAuthoriseQueryResponse(Response response, String expectedIdTokenJti) {
        assertEquals(Status.OK, response.getStatus());
        final MutableUri locationUri = getLocationUri(response);
        try {
            final Optional<String> idToken = new Form().fromQueryString(locationUri.getQuery()).get(ID_TOKEN).stream().findFirst();
            assertTrue(idToken.isPresent());
            jwtReSignerTestResourceManager.validateIdTokenHasBeenReSigned(expectedIdTokenJti, idToken.get());
        } catch (ParseException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static MutableUri getLocationUri(Response response) {
        final Header location = response.getHeaders().get("location");
        try {
            return MutableUri.uri(location.getFirstValue());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

}