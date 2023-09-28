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
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Util to sign objects <br/>
 * Implementation of {@link SignUtil}
 */
public class SignPayloadUtil implements SignUtil {

    private static final Logger logger = LoggerFactory.getLogger(SignPayloadUtil.class);
    private final SigningManager signingManager;
    private final Purpose<SigningKey> signingKeyPurpose;
    private final Map<String, Object> critHeaderClaims;

    private final String signingKeyId;
    private final String algorithm;
    private final String kid;
    public SignPayloadUtil(
            SecretsProvider secretsProvider,
            Map<String, Object> critHeaderClaims,
            String signingKeyId,
            String kid,
            String algorithm
    ) {
        Reject.ifNull(secretsProvider, "secretsProvider must be supplied");
        Reject.ifNull(kid, "kid must be supplied");
        Reject.ifNull(signingKeyId, "signingKeyId must be supplied");
        Reject.ifNull(algorithm, "algorithm must be supplied");
        this.signingManager = new SigningManager(secretsProvider);
        this.signingKeyId = signingKeyId;
        this.kid = kid;
        this.critHeaderClaims = critHeaderClaims == null ? Collections.EMPTY_MAP : critHeaderClaims;
        this.algorithm = algorithm;
        this.signingKeyPurpose = Purpose.purpose(signingKeyId, SigningKey.class);
    }


    @Override
    public String sign(final Map<String, Object> payload) {
        Reject.ifNull(payload, "payload must be supplied");
        Reject.ifTrue(payload.isEmpty(),"payload map must not be empty");
        logger.debug("Payload to be signed:\n {}\n", payload);
        Promise<SigningHandler, NoSuchSecretException> signingHandler = signingManager.newSigningHandler(signingKeyPurpose);
        try {
            final JwtClaimsSet jwtClaimsSet = new JwtClaimsSet(payload);

            SignedJwtBuilderImpl signedJwtBuilder = new JwtBuilderFactory()
                    .jws(signingHandler.getOrThrow())
                    .headers()
                    .alg(JwsAlgorithm.parseAlgorithm(algorithm))
                    .kid(kid)
                    .done()
                    .claims(jwtClaimsSet);

            SignedJwt signedJwt = signedJwtBuilder.asJwt();


            if(!critHeaderClaims.isEmpty()) {
                logger.debug("Adding critical header claims {}", critHeaderClaims);
                signedJwt.getHeader().put("crit", critHeaderClaims.keySet().stream().collect(Collectors.toList()));
                critHeaderClaims.forEach((k, v) -> signedJwt.getHeader().put(k, v));
            }

            return signedJwt.build();
        } catch (java.lang.Exception e) {
            logger.error("Error signing the payload : " + e);
            throw new RuntimeException(e);
        }
    }
}
