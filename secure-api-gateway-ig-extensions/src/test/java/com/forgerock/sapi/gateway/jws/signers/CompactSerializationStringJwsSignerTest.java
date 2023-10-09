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
package com.forgerock.sapi.gateway.jws.signers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.nimbusds.jwt.SignedJWT;

/**
 * Unit test for {@link CompactSerializationStringJwsSignerTest}
 */
public class CompactSerializationStringJwsSignerTest extends CompactSerializationJwsSignerTest {

    @Test
    void shouldSignPayload() throws Exception {
        // Given
        final CompactSerializationStringJwsSigner jwsSigner = new CompactSerializationStringJwsSigner(
                getSecretsProvider(),
                SIGNING_KEY_ID,
                KID,
                ALGORITHM
        );
        // When
        final Promise<String, SapiJwsSignerException> result = jwsSigner.sign(aValidPayloadAsString(), critClaims);
        // Then
        assertThat(result).isNotNull();
        final String signerResult = result.get();
        assertThat(signerResult).isNotNull();
        final SignedJWT signedJwt = SignedJWT.parse(signerResult);
        validateSignature(signedJwt);
        validateSignedJwt(signedJwt);
        validateCritClaims(signedJwt.getHeader());
    }

    @Test
    void shouldSignPayloadNoCritClaims() throws Exception {
        // Given
        final CompactSerializationStringJwsSigner jwsSigner = new CompactSerializationStringJwsSigner(
                getSecretsProvider(),
                SIGNING_KEY_ID,
                KID,
                ALGORITHM
        );
        // When
        final Promise<String, SapiJwsSignerException> result = jwsSigner.sign(aValidPayloadAsString(), null);
        // Then
        assertThat(result).isNotNull();
        final String signerResult = result.get();
        assertThat(signerResult).isNotNull();
        final SignedJWT signedJwt = SignedJWT.parse(signerResult);
        validateSignature(signedJwt);
        validateSignedJwt(signedJwt);
    }

    @Test
    void shouldRaiseExceptionNullParameter() {
        // Given / When / Then
        assertThrows(
                NullPointerException.class,
                () -> new CompactSerializationStringJwsSigner(
                        null,
                        SIGNING_KEY_ID,
                        KID,
                        ALGORITHM
                )
        );
    }

    @Test
    void shouldRaisePayloadNullException() throws Exception {
        // Given
        final CompactSerializationStringJwsSigner jwsSigner = new CompactSerializationStringJwsSigner(
                getSecretsProvider(),
                SIGNING_KEY_ID,
                KID,
                ALGORITHM
        );
        // When
        final Promise<String, SapiJwsSignerException> result = jwsSigner.sign(null, null);
        // Then
        assertThat(result).isNotNull();
        assertThat(assertThrows(SapiJwsSignerException.class, () -> result.getOrThrow()).getMessage())
                .isEqualTo(
                        String.format(
                                "Compute signature %s: The payload cannot be null, empty or blank",
                                SapiJwsSignerException.class.getSimpleName()
                        )
                );
    }

    @Test
    void shouldRaiseSigningKeyException() throws Exception {
        // Given
        final String signingKeyId = "wrongKeyId";
        final SigningKey signingKey = getSigningKey(signingKeyId);

        final SecretsProvider secretsProvider = getSecretsProvider()
                .useSpecificSecretForPurpose(
                        Purpose.purpose(SIGNING_KEY_ID, SigningKey.class),
                        signingKey
                );
        final CompactSerializationStringJwsSigner jwsSigner = new CompactSerializationStringJwsSigner(
                secretsProvider,
                signingKeyId,
                KID,
                ALGORITHM
        );
        // When
        final Promise<String, SapiJwsSignerException> result = jwsSigner.sign(aValidPayloadAsString(), critClaims);

        // Then
        assertThat(result).isNotNull();
        assertThat(assertThrows(SapiJwsSignerException.class, () -> result.getOrThrow()).getMessage())
                .isEqualTo(
                        String.format(
                                "Compute signature %s: No secret configured for purpose %s",
                                NoSuchSecretException.class.getSimpleName(),
                                signingKeyId
                        )
                );
    }

    @Test
    void shouldRaiseAlgorithmException() throws Exception {
        // Given
        final CompactSerializationStringJwsSigner jwsSigner = new CompactSerializationStringJwsSigner(
                getSecretsProvider(),
                SIGNING_KEY_ID,
                KID,
                "WRONG-ALG"
        );
        // When
        final Promise<String, SapiJwsSignerException> result = jwsSigner.sign(aValidPayloadAsString(), critClaims);
        // Then
        assertThat(result).isNotNull();
        assertThat(assertThrows(SapiJwsSignerException.class, () -> result.getOrThrow()).getMessage())
                .isEqualTo(String.format(
                                "Compute signature %s: Unknown Signing Algorithm",
                                IllegalArgumentException.class.getSimpleName()
                        )
                );
    }

//    private SigningKey getSigningKey(String signingKeyId) throws Exception {
//        return new SecretBuilder().secretKey(keyPair.getPrivate())
//                .stableId(signingKeyId)
//                .keyUsages(singleton(SIGN))
//                .expiresAt(Instant.MAX)
//                .build(Purpose.SIGN);
//    }
//
//    private SecretsProvider getSecretsProvider() throws Exception {
//        SecretsProvider secretsProvider = new SecretsProvider(Clock.systemUTC());
//        secretsProvider.useSpecificSecretForPurpose(Purpose.purpose(SIGNING_KEY_ID, SigningKey.class),
//                getSigningKey(SIGNING_KEY_ID));
//        return secretsProvider;
//    }
//
//    private void validateSignature(SignedJWT signedJwt) {
//        try {
//            signedJwt.verify(rsaJwtVerifier);
//        } catch (JOSEException e) {
//            fail("Failed to verify signedJwt was signed by " + SIGNING_KEY_ID, e);
//        }
//    }
//
//    private void validateSignedJwt(SignedJWT signedJwt) throws ParseException {
//        // Valid the header and claims match what is expected
//        final JWSHeader header = signedJwt.getHeader();
//        assertEquals(JWSAlgorithm.PS256, header.getAlgorithm());
//        assertEquals(KID, header.getKeyID());
//        final JWTClaimsSet jwtClaimsSet = signedJwt.getJWTClaimsSet();
//        assertEquals("https://examplebank.com/", jwtClaimsSet.getIssuer());
//        assertEquals("https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003", jwtClaimsSet.getSubject());
//        assertEquals(List.of(AUD), jwtClaimsSet.getAudience());
//        assertEquals(TXN, jwtClaimsSet.getClaim("txn"));
//        assertEquals(JTI, jwtClaimsSet.getJWTID());
//    }
//
//    private void validateCritClaims(JWSHeader header) {
//        assertEquals(header.getCriticalParams(), critClaims.keySet());
//        critClaims.forEach((k, v) -> {
//            assertThat(header.getCustomParam(k)).isNotNull().isEqualTo(v);
//        });
//    }
//
//    private String getPayloadMap() throws IOException {
//        return new String(Json.writeJson(
//        Map.of(
//                "iss", "https://examplebank.com/",
//                "iat", 1516239022,
//                "jti", JTI,
//                "sub", "https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003",
//                "aud", AUD,
//                "txn", TXN,
//                "toe", 1516239022,
//                "events", Map.of(
//                        "urn:uk:org:openbanking:events:resource-update", Map.of(
//                                "subject", Map.of(
//                                        "subject_type", "http://openbanking.org.uk/rid_http://openbanking.org.uk/rty",
//                                        "http://openbanking.org.uk/rid", "pmt-7290-003",
//                                        "http://openbanking.org.uk/rlk", Map.of("version", "v3.0",
//                                                "link", "https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003"
//                                        )
//                                )
//                        )
//                )
//        )
//        ), StandardCharsets.UTF_8);
//    }

    @Nested
    public class HeapletTests {
        private HeapImpl heap;

        @BeforeEach
        public void setUp() throws Exception {
            heap = new HeapImpl(Name.of("defaultHeap"));
            heap.put("SecretsProvider-ASPSP", getSecretsProvider());
        }

        @AfterEach
        public void tearDown() {
            heap.destroy();
        }

        @Test
        void failIfServiceProviderIsMissing() {
            // Given
            final Name defaultSigner = Name.of("defaultSigner");
            final JsonValue configuration = json(
                    object(
                            field("signingKeyId", SIGNING_KEY_ID),
                            field("kid", KID),
                            field("algorithm", ALGORITHM)
                    ));
            // When
            final JsonValueException heapException = assertThrows(JsonValueException.class,
                    () -> new CompactSerializationMapJwsSigner.Heaplet().create(
                            defaultSigner,
                            configuration
                            , heap)
            );
            // Then
            assertEquals("/secretsProvider: Expecting a value", heapException.getMessage());
        }

        @Test
        void failIfSigningKeyIdIsMissing() {
            // Given
            final Name defaultSigner = Name.of("defaultSigner");
            final JsonValue configuration = json(
                    object(
                            field("secretsProvider", "SecretsProvider-ASPSP"),
                            field("kid", KID),
                            field("algorithm", ALGORITHM)
                    ));
            // When
            final JsonValueException heapException = assertThrows(JsonValueException.class,
                    () -> new CompactSerializationMapJwsSigner.Heaplet().create(
                            defaultSigner,
                            configuration
                            , heap)
            );
            // Then
            assertEquals("/signingKeyId: Expecting a value", heapException.getMessage());
        }

        @Test
        void failIfKidIsMissing() {
            // Given
            final Name defaultSigner = Name.of("defaultSigner");
            final JsonValue configuration = json(
                    object(
                            field("secretsProvider", "SecretsProvider-ASPSP"),
                            field("signingKeyId", SIGNING_KEY_ID),
                            field("algorithm", ALGORITHM)
                    ));
            // When
            final JsonValueException heapException = assertThrows(JsonValueException.class,
                    () -> new CompactSerializationMapJwsSigner.Heaplet().create(
                            defaultSigner,
                            configuration
                            , heap)
            );
            // Then
            assertEquals("/kid: Expecting a value", heapException.getMessage());
        }

        @Test
        void failIfAlgorithmIsMissing() {
            // Given
            final Name defaultSigner = Name.of("defaultSigner");
            final JsonValue configuration = json(
                    object(
                            field("secretsProvider", "SecretsProvider-ASPSP"),
                            field("signingKeyId", SIGNING_KEY_ID),
                            field("kid", KID)
                    ));
            // When
            final JsonValueException heapException = assertThrows(JsonValueException.class,
                    () -> new CompactSerializationMapJwsSigner.Heaplet().create(
                            defaultSigner,
                            configuration
                            , heap)
            );
            // Then
            assertEquals("/algorithm: Expecting a value", heapException.getMessage());
        }

        @Test
        void successfullyCreated() throws Exception {
            // Given
            final Name defaultSigner = Name.of("defaultSigner");
            final JsonValue configuration = json(
                    object(
                            field("secretsProvider", "SecretsProvider-ASPSP"),
                            field("signingKeyId", SIGNING_KEY_ID),
                            field("kid", KID),
                            field("algorithm", ALGORITHM)
                    ));
            // When
            final CompactSerializationMapJwsSigner jwsSigner = (CompactSerializationMapJwsSigner) new CompactSerializationMapJwsSigner.Heaplet().create(
                    defaultSigner,
                    configuration
                    , heap);
            // Then
            assertNotNull(jwsSigner);
            // When
            final Promise<String, SapiJwsSignerException> result = jwsSigner.sign(aValidPayloadMap(), critClaims);
            // Then
            assertThat(result).isNotNull();
            final String signerResult = result.get();
            assertThat(signerResult).isNotNull();
            final SignedJWT signedJwt = SignedJWT.parse(signerResult);
            validateSignature(signedJwt);
            validateSignedJwt(signedJwt);
            validateCritClaims(signedJwt.getHeader());
        }
    }
}
