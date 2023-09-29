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

import static org.forgerock.openig.secrets.SecretsProviderHeaplet.secretsProvider;

import java.util.Collections;
import java.util.Map;
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
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link SapiJwsSigner}
 */
public class DefaultSapiJwsSigner implements SapiJwsSigner<DefaultSapiJwsSigner> {

    private static final Logger logger = LoggerFactory.getLogger(DefaultSapiJwsSigner.class);
    private final SigningManager signingManager;
    private final Purpose<SigningKey> signingKeyPurpose;
    private Map<String, Object> critHeaderClaims;
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
        this.critHeaderClaims = Collections.EMPTY_MAP;
    }


    @Override
    public String sign(final Map<String, Object> payload) throws Exception {
        Reject.ifNull(payload, "payload must be supplied");
        Reject.ifTrue(payload.isEmpty(), "payload map must not be empty");

        logger.debug("Payload to be signed:\n {}\n", payload);

        Promise<SigningHandler, NoSuchSecretException> signingHandler = signingManager.newSigningHandler(signingKeyPurpose);

        return signingHandler.then(sHandler -> {
            final JwtClaimsSet jwtClaimsSet = new JwtClaimsSet(payload);
            SignedJwtBuilderImpl signedJwtBuilder = new JwtBuilderFactory()
                    .jws(sHandler)
                    .headers()
                    .alg(JwsAlgorithm.parseAlgorithm(algorithm))
                    .kid(kid)
                    .done()
                    .claims(jwtClaimsSet);

            SignedJwt signedJwt = signedJwtBuilder.asJwt();

            addCriticalClaims(signedJwt);

            return signedJwt.build();

        }).getOrThrow();
    }

    @Override
    public DefaultSapiJwsSigner critClaims(final Map<String, Object> criticalHeaderClaims) {
        this.critHeaderClaims = criticalHeaderClaims == null ? Collections.EMPTY_MAP : criticalHeaderClaims;
        return this;
    }

    private void addCriticalClaims(SignedJwt signedJwt) {
        if (!critHeaderClaims.isEmpty()) {
            logger.debug("Adding critical header claims {}", critHeaderClaims);
            signedJwt.getHeader().put(CRIT_CLAIM, critHeaderClaims.keySet().stream().collect(Collectors.toList()));
            critHeaderClaims.forEach((k, v) -> signedJwt.getHeader().put(k, v));
        }
    }

    /**
     * Basic heaplet to allow RsaJwtSignatureValidator to be created via IG config
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
//            final String clientId = config.get(CONFIG_CLIENT_ID).as(evaluatedWithHeapProperties()).required().asString();
            final SecretsProvider secretsProvider = config.get("secretsProvider").required()
                    .as(secretsProvider(heap));
            final String signingKeyId = config.get("signingKeyId").required().asString();
            final String kid = config.get("kid").as(evaluatedWithHeapProperties()).required().asString();
            final String algorithm = config.get("algorithm").required().asString();
            return new DefaultSapiJwsSigner(secretsProvider, signingKeyId, kid, algorithm);
        }
    }
}
