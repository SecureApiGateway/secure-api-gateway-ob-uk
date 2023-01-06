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

import java.security.cert.CertificateException;

import java.security.cert.X509Certificate;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.util.CryptoUtils;

class DefaultTransportCertValidatorTest {

    private static X509Certificate TEST_TLS_CERT;
    private static JWKSet TEST_JWKS;

    public static final String TLS_KEY_USE = "tls";

    @BeforeAll
    public static void beforeAll() throws Exception {
        final Pair<X509Certificate, JWKSet> transportCertPemAndJwkSet = CryptoUtils.generateTestTransportCertAndJwks(TLS_KEY_USE);
        TEST_TLS_CERT = transportCertPemAndJwkSet.getFirst();
        TEST_JWKS = transportCertPemAndJwkSet.getSecond();
    }

    @Test
    void testValidCertAndUse() throws CertificateException {
        new DefaultTransportCertValidator(TLS_KEY_USE).validate(TEST_TLS_CERT, TEST_JWKS);
    }

    @Test
    void testValidCertNoUseCheck() throws CertificateException {
        new DefaultTransportCertValidator().validate(TEST_TLS_CERT, TEST_JWKS);
    }

    @Test
    void failsWhenCertMatchButUseDoesNot() throws CertificateException {
        final CertificateException certificateException = Assertions.assertThrows(CertificateException.class,
                () -> new DefaultTransportCertValidator("blah").validate(TEST_TLS_CERT, TEST_JWKS));

        Assertions.assertEquals("Failed to find JWK entry in provided JWKSet which matches the X509 cert", certificateException.getMessage());
    }
}