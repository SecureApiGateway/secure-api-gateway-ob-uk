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
package com.forgerock.sapi.gateway.sign;

import static java.util.Collections.singleton;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.secrets.keys.KeyUsage.SIGN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretBuilder;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class SignPayloadUtilTest {

    private static final String KID = "xcJeVytTkFL21lHIUVkAd6QVi4M";
    private static final String AUD = "7umx5nTR33811QyQfi";
    private static final String ALGORITHM = "PS256";
    private Map<String, Object> critClaims;
    private String signingKeyId = KID;
    private KeyPair keyPair;
    private final RSASSAVerifier rsaJwtVerifier;

    public SignPayloadUtilTest() {
        keyPair = CryptoUtils.generateRsaKeyPair();
        rsaJwtVerifier = new RSASSAVerifier((RSAPublicKey) keyPair.getPublic());
        this.critClaims = Map.of(
                "http://openbanking.org.uk/iat", System.currentTimeMillis() / 1000,
                "http://openbanking.org.uk/iss", "ISS_ORG_ID",
                "http://openbanking.org.uk/tan", "openbanking.org.uk"
        );
    }

    @Test
    void shouldSignPayload() throws Exception {
        // Given
        SignPayloadUtil signPayload = new SignPayloadUtil(
                getSecretsProvider(),
                critClaims,
                signingKeyId,
                KID,
                ALGORITHM
        );
        // When
        String result = signPayload.sign(getPayloadMap());
        // Then
        assertThat(result).isNotNull();
        validateSignature(result);
    }

    @Test
    void shouldRaiseExceptionNullParameter() {
        // Given / When / Then
        assertThrows(
                NullPointerException.class,
                () -> new SignPayloadUtil(
                        null,
                        critClaims,
                        signingKeyId,
                        KID,
                        ALGORITHM
                )
        );
    }

    @Test
    void shouldRaiseSignException() throws Exception {
        // Given
        String signingKeyId = "wrongKeyId";
        SigningKey signingKey = getSigningKey(signingKeyId);

        SecretsProvider secretsProvider = getSecretsProvider()
                .useSpecificSecretForPurpose(
                        Purpose.purpose("anotherKeyId", SigningKey.class),
                        signingKey
                );
        SignPayloadUtil signPayload = new SignPayloadUtil(
                secretsProvider,
                critClaims,
                signingKeyId,
                KID,
                ALGORITHM
        );
        // Then
        assertThrows(
                RuntimeException.class, () -> signPayload.sign(getPayloadMap())
        );
    }

    private SigningKey getSigningKey(String signingKeyId) throws Exception {
        return new SecretBuilder().secretKey(keyPair.getPrivate())
                .stableId(signingKeyId)
                .keyUsages(singleton(SIGN))
                .expiresAt(Instant.MAX)
                .build(Purpose.SIGN);
    }

    private SecretsProvider getSecretsProvider() throws Exception {
        SecretsProvider secretsProvider = new SecretsProvider(Clock.systemUTC());
        secretsProvider.useSpecificSecretForPurpose(Purpose.purpose(signingKeyId, SigningKey.class),
                getSigningKey(signingKeyId));
        return secretsProvider;
    }

    private void validateSignature(String signedJwt) throws ParseException {
        final SignedJWT jwtToVerify = SignedJWT.parse(signedJwt);
        try {
            jwtToVerify.verify(rsaJwtVerifier);
        } catch (JOSEException e) {
            fail("Failed to verify signedJwt was signed by " + signingKeyId, e);
        }

        // Valid the id_token header and claims match what is expected
        final JWSHeader header = jwtToVerify.getHeader();
        assertEquals(JWSAlgorithm.PS256, header.getAlgorithm());
        assertEquals(KID, header.getKeyID());
        final JWTClaimsSet jwtClaimsSet = jwtToVerify.getJWTClaimsSet();
        assertEquals("https://examplebank.com/", jwtClaimsSet.getIssuer());
        assertEquals("https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003", jwtClaimsSet.getSubject());
        assertEquals(List.of(AUD), jwtClaimsSet.getAudience());
        assertEquals("dfc51628-3479-4b81-ad60-210b43d02306", jwtClaimsSet.getClaim("txn"));
        assertEquals("b460a07c-4962-43d1-85ee-9dc10fbb8f6c", jwtClaimsSet.getJWTID());
    }

    private ImmutableMap<String, Object> getPayloadMap() {
        return ImmutableMap.<String, Object>builder()
                .put("iss", "https://examplebank.com/")
                .put("iat", 1516239022)
                .put("jti", "b460a07c-4962-43d1-85ee-9dc10fbb8f6c")
                .put("sub", "https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003")
                .put("aud", AUD)
                .put("txn", "dfc51628-3479-4b81-ad60-210b43d02306")
                .put("toe", 1516239022)
                .put("events", Map.of(
                                "urn:uk:org:openbanking:events:resource-update", Map.of(
                                        "subject", Map.of(
                                                "subject_type", "http://openbanking.org.uk/rid_http://openbanking.org.uk/rty",
                                                "http://openbanking.org.uk/rid", "pmt-7290-003",
                                                "http://openbanking.org.uk/rlk", Map.of("version", "v3.0",
                                                        "link", "https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003"
                                                )
                                        )
                                )
                        )
                ).build();
    }
}
