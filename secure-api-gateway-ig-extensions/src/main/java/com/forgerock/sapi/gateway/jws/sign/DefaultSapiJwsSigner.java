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
package com.forgerock.sapi.gateway.jws.sign;

import static org.forgerock.openig.secrets.SecretsProviderHeaplet.secretsProvider;

import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.forgerock.json.jose.builders.JwsHeaderBuilder;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.util.Strings;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link SapiJwsSigner}
 * <p>
 * A default JWS signer. <br/>
 * Provides signing functionality for use by the filters and/or the IG scripts<br/>
 * @see DefaultSapiJwsSigner.Heaplet
 */
public class DefaultSapiJwsSigner implements SapiJwsSigner {

    private static final Logger logger = LoggerFactory.getLogger(DefaultSapiJwsSigner.class);
    private final SigningManager signingManager;
    private final Purpose<SigningKey> signingKeyPurpose;
    private final String algorithm;
    private final String kid;

    public DefaultSapiJwsSigner(
            SecretsProvider secretsProvider,
            String signingKeyId,
            String kid,
            String algorithm
    ) {
        this.signingManager = new SigningManager(secretsProvider);
        this.kid = kid;
        this.algorithm = algorithm;
        this.signingKeyPurpose = Purpose.purpose(signingKeyId, SigningKey.class);
    }

    @Override
    public Promise<String, SapiJwsSignerException> sign(
            final Map<String, Object> payload,
            final Map<String, Object> criticalHeaderClaims
    ) {
        if (Objects.isNull(payload) || payload.isEmpty()) {
            return Promises.newExceptionPromise(
                    new SapiJwsSignerException("Failed to compute the signature, The payload cannot be null")
            );
        }
        return signingManager.newSigningHandler(signingKeyPurpose)
                .then(signingHandler -> sign(signingHandler, payload, criticalHeaderClaims),
                        noSuchSecretException -> {
                            String error = Strings.joinAsString(
                                    ", ",
                                    "Failed to create Signing Handler",
                                    noSuchSecretException.getMessage()
                            );
                            logger.error(error, noSuchSecretException);
                            throw new SapiJwsSignerException(error, noSuchSecretException);
                        }
                );
    }

    private String sign(
            SigningHandler signingHandler,
            final Map<String, Object> payload,
            final Map<String, Object> criticalHeaderClaims
    ) throws SapiJwsSignerException {
        try {
            final JwtClaimsSet jwtClaimsSet = new JwtClaimsSet(payload);

            JwsHeaderBuilder jwsHeaderBuilder = new JwtBuilderFactory()
                    .jws(signingHandler)
                    .headers()
                    .alg(JwsAlgorithm.parseAlgorithm(algorithm))
                    .kid(kid);

            addCriticalClaims(jwsHeaderBuilder, criticalHeaderClaims);

            return jwsHeaderBuilder.done().claims(jwtClaimsSet).build();

        } catch (Exception e) {
            String error = Strings.joinAsString(
                    ", ",
                    "Failed to compute the signature",
                    e.getMessage()
            );
            logger.error(error, e.getCause());
            throw new SapiJwsSignerException(error, e);
        }
    }

    private void addCriticalClaims(JwsHeaderBuilder jwsHeaderBuilder, final Map<String, Object> criticalHeaderClaims) {
        if (!Objects.isNull(criticalHeaderClaims) && !criticalHeaderClaims.isEmpty()) {
            jwsHeaderBuilder.crit(criticalHeaderClaims.keySet().stream().collect(Collectors.toList()));
            criticalHeaderClaims.forEach((k, v) -> jwsHeaderBuilder.header(k, v));
        }
    }

    /**
     * Heaplet used to create {@link DefaultSapiJwsSigner} objects
     * <p/>
     * Mandatory fields:
     * <ul>
     *     <li>secretsProvider: The SecretsProvider object to query for the 'signingKeyId' in the keystore</li>
     *     <li>signingKeyId: The signing key id name to identify the private key in the keystore to sign a JWT</li>
     *     <li>kid: Key ID to build the JWT header, used to validate the signature via JWKs</li>
     *     <li>algorithm: The name of the algorithm to use to sign the JWT</li>
     * </ul>
     * Example config:
     * <pre>{@code
     * {
     *     "comment": "Default payload signer",
     *     "name": "DefaultSapiJwsSigner-RSASSA-PSS",
     *     "type": "com.forgerock.sapi.gateway.jwks.sign.DefaultSapiJwsSigner",
     *     "config": {
     *         "algorithm": "PS256",
     *         "signingKeyId": "jwt.signer",
     *         "kid": "&{ig.ob.aspsp.signing.kid}",
     *         "secretsProvider": "SecretsProvider-ASPSP"
     *     }
     * }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final SecretsProvider secretsProvider = config.get("secretsProvider").required()
                    .as(secretsProvider(heap));
            final String signingKeyId = config.get("signingKeyId").required().asString();
            final String kid = config.get("kid").as(evaluatedWithHeapProperties()).required().asString();
            final String algorithm = config.get("algorithm").required().asString();
            return new DefaultSapiJwsSigner(secretsProvider, signingKeyId, kid, algorithm);
        }
    }
}
