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
 * Unit test for {@link CompactSerializationMapJwsSigner}
 */
public class CompactSerializationMapJwsSignerTest extends CompactSerializationJwsSignerTest {

    @Test
    void shouldSignPayload() throws Exception {
        // Given
        final CompactSerializationMapJwsSigner jwsSigner = new CompactSerializationMapJwsSigner(
                getSecretsProvider(),
                SIGNING_KEY_ID,
                KID,
                ALGORITHM
        );
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

    @Test
    void shouldSignPayloadNoCritClaims() throws Exception {
        // Given
        final CompactSerializationMapJwsSigner jwsSigner = new CompactSerializationMapJwsSigner(
                getSecretsProvider(),
                SIGNING_KEY_ID,
                KID,
                ALGORITHM
        );
        // When
        final Promise<String, SapiJwsSignerException> result = jwsSigner.sign(aValidPayloadMap(), null);
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
                () -> new CompactSerializationMapJwsSigner(
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
        final CompactSerializationMapJwsSigner jwsSigner = new CompactSerializationMapJwsSigner(
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
                                "Compute signature %s: The payload cannot be null or empty",
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
        final CompactSerializationMapJwsSigner jwsSigner = new CompactSerializationMapJwsSigner(
                secretsProvider,
                signingKeyId,
                KID,
                ALGORITHM
        );
        // When
        final Promise<String, SapiJwsSignerException> result = jwsSigner.sign(aValidPayloadMap(), critClaims);

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
        final CompactSerializationMapJwsSigner jwsSigner = new CompactSerializationMapJwsSigner(
                getSecretsProvider(),
                SIGNING_KEY_ID,
                KID,
                "WRONG-ALG"
        );
        // When
        final Promise<String, SapiJwsSignerException> result = jwsSigner.sign(aValidPayloadMap(), critClaims);
        // Then
        assertThat(result).isNotNull();
        assertThat(assertThrows(SapiJwsSignerException.class, () -> result.getOrThrow()).getMessage())
                .isEqualTo(String.format(
                                "Compute signature %s: Unknown Signing Algorithm",
                                IllegalArgumentException.class.getSimpleName()
                        )
                );
    }

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
