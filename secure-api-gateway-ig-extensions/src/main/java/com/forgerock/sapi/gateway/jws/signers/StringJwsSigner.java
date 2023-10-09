package com.forgerock.sapi.gateway.jws.signers;

import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;

import org.forgerock.http.util.Json;
import org.forgerock.json.jose.builders.JwsHeaderBuilder;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class StringJwsSigner implements JwsSigner<String> {

    private static final Logger logger = LoggerFactory.getLogger(StringJwsSigner.class);

    protected final SigningManager signingManager;
    protected final Purpose<SigningKey> signingKeyPurpose;
    protected final String algorithm;
    protected final String kid;

    protected StringJwsSigner(
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

    protected String sign(
            SigningHandler signingHandler,
            String payload,
            final Map<String, Object> criticalHeaderClaims
    ) throws SapiJwsSignerException {
        try {
            Map<String, Object> payloadMapped = (Map<String, Object>) Json.readJson(payload);
            final JwtClaimsSet jwtClaimsSet = new JwtClaimsSet(payloadMapped);

            JwsHeaderBuilder jwsHeaderBuilder = new JwtBuilderFactory()
                    .jws(signingHandler)
                    .headers()
                    .alg(JwsAlgorithm.parseAlgorithm(algorithm))
                    .kid(kid);

            addCritHeaderClaims(jwsHeaderBuilder, criticalHeaderClaims);

            return jwsHeaderBuilder.done().claims(jwtClaimsSet).build();

        } catch (Exception e) {
            throw sapiJwsSignerException(e);
        }
    }

    private void addCritHeaderClaims(JwsHeaderBuilder jwsHeaderBuilder, final Map<String, Object> criticalHeaderClaims) {
        if (!(criticalHeaderClaims == null) && !criticalHeaderClaims.isEmpty()) {
            jwsHeaderBuilder.crit(new ArrayList<>(criticalHeaderClaims.keySet()));
            criticalHeaderClaims.forEach(jwsHeaderBuilder::header);
        }
    }

    protected SapiJwsSignerException sapiJwsSignerException(Exception exception) {
        String reason = buildErrorMessage(exception.getClass().getSimpleName(), exception.getMessage());
        logger.error(reason, exception);
        return new SapiJwsSignerException(reason, exception);
    }
}
