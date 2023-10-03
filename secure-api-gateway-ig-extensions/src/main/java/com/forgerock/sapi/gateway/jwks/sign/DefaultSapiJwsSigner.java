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
package com.forgerock.sapi.gateway.jwks.sign;

import static org.forgerock.openig.secrets.SecretsProviderHeaplet.secretsProvider;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.builders.SignedJwtBuilderImpl;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link SapiJwsSigner}
 * <p>
 * This default JWS signer is configured in the IG configuration Heap to be used in filters<br/>
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
    public Promise<SapiJwsSignerResult, NeverThrowsException> sign(
            final Map<String, Object> payload,
            final Map<String, Object> criticalHeaderClaims
    ) {
        return signingManager.newSigningHandler(signingKeyPurpose).then(signingHandler -> {
            try {
                return new DefaultSapiJwsSignerResult(sign(signingHandler, payload, criticalHeaderClaims));
            } catch (SapiJwsSignerException sapiJwsSignerException) {
                return new DefaultSapiJwsSignerResult(List.of(sapiJwsSignerException.getMessage()));
            }
        }, noSuchSecretException -> {
            logger.error("Failed to create signingHandler, {}", noSuchSecretException.getMessage());
            return new DefaultSapiJwsSignerResult(List.of(noSuchSecretException.getMessage()));
        });
    }

    private String sign(
            SigningHandler signingHandler,
            final Map<String, Object> payload,
            final Map<String, Object> criticalHeaderClaims
    ) throws SapiJwsSignerException {
        try {
            final JwtClaimsSet jwtClaimsSet = new JwtClaimsSet(payload);
            SignedJwtBuilderImpl signedJwtBuilder = new JwtBuilderFactory()
                    .jws(signingHandler)
                    .headers()
                    .alg(JwsAlgorithm.parseAlgorithm(algorithm))
                    .kid(kid)
                    .done()
                    .claims(jwtClaimsSet);

            SignedJwt signedJwt = signedJwtBuilder.asJwt();
            if (!Objects.isNull(criticalHeaderClaims) && !criticalHeaderClaims.isEmpty()) {
                logger.debug("Adding critical header claims {}", criticalHeaderClaims);
                signedJwt.getHeader().put(CRIT_CLAIM, criticalHeaderClaims.keySet().stream().collect(Collectors.toList()));
                criticalHeaderClaims.forEach((k, v) -> signedJwt.getHeader().put(k, v));
            }

            return signedJwt.build();
        } catch (Exception e) {
            logger.error("Error signing, {}", e.getMessage(), e);
            throw new SapiJwsSignerException(e.getMessage());
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
