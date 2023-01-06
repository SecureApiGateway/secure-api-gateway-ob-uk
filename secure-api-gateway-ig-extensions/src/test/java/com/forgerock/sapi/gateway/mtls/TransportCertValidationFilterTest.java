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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.Pair;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.jwks.FetchApiClientJwksFilter;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

class TransportCertValidationFilterTest {

    /**
     * TEST_TLS_CERT in URL encoded form, as provided by nginx
     */
    private static String TEST_TLS_CERT;
    /**
     * JWKSet containing TEST_TLS_CERT plus others
     */
    private static JWKSet TEST_JWKS;

    @BeforeAll
    public static void beforeAll() throws Exception {
        final Pair<X509Certificate, JWKSet> testTransportCertAndJwks = CryptoUtils.generateTestTransportCertAndJwks("tls");
        TEST_TLS_CERT = URLEncoder.encode(CryptoUtils.convertToPem(testTransportCertAndJwks.getFirst()), Charset.defaultCharset());
        TEST_JWKS = testTransportCertAndJwks.getSecond();
    }

    @Test
    public void testValidCert() throws ExecutionException, InterruptedException, TimeoutException {
        final String certificateHeaderName = "ssl-client-cert";
        final CertificateFromHeaderSupplier clientTlsCertificateSupplier = new CertificateFromHeaderSupplier(certificateHeaderName);
        final DefaultTransportCertValidator certValidator = new DefaultTransportCertValidator("tls");
        final TransportCertValidationFilter transportCertValidationFilter = new TransportCertValidationFilter(clientTlsCertificateSupplier, certValidator);

        final Context context = createContextWithJwksAttribute(TEST_JWKS);
        final Request request = createRequestWithCertHeader(certificateHeaderName, TEST_TLS_CERT);

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(context, request, responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(200, response.getStatus().getCode(), "HTTP Response Code");
        assertTrue(responseHandler.hasBeenInteractedWith(), "ResponseHandler must be called");
    }

    private static Request createRequestWithCertHeader(String certificateHeaderName, String certValue) {
        final Request request = new Request().setMethod("GET");
        request.addHeaders(new GenericHeader(certificateHeaderName, certValue));
        return request;
    }

    private static Context createContextWithJwksAttribute(JWKSet jwkSet) {
        final Context context = new AttributesContext(new TransactionIdContext(new RootContext(), new TransactionId("1234")));
        addJwkSetToAttributesContext(context, jwkSet);
        return context;
    }

    private static void addJwkSetToAttributesContext(Context context, JWKSet jwkSet) {
        context.asContext(AttributesContext.class).getAttributes().put(FetchApiClientJwksFilter.API_CLIENT_JWKS_ATTR_KEY, jwkSet);
    }
}