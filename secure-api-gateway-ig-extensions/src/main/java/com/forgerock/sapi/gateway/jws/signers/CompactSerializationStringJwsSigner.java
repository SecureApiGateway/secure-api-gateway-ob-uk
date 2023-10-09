package com.forgerock.sapi.gateway.jws.signers;

import static org.forgerock.openig.secrets.SecretsProviderHeaplet.secretsProvider;

import java.util.Map;

import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CompactSerializationStringJwsSigner extends StringJwsSigner {

    private static final Logger logger = LoggerFactory.getLogger(CompactSerializationStringJwsSigner.class);

    protected CompactSerializationStringJwsSigner(
            SecretsProvider secretsProvider,
            String signingKeyId,
            String kid,
            String algorithm
    ) {
        super(secretsProvider, signingKeyId, kid, algorithm);
    }

    @Override
    public Promise<String, SapiJwsSignerException> sign(
            final String payload,
            final Map<String, Object> criticalHeaderClaims
    ) {
        if (payload == null || payload.isEmpty() || payload.isBlank()) {
            String reason = buildErrorMessage(
                    SapiJwsSignerException.class.getSimpleName(),
                    "The payload cannot be null, empty or blank"
            );
            logger.error(reason);
            return Promises.newExceptionPromise(new SapiJwsSignerException(reason));
        }
        return signingManager.newSigningHandler(signingKeyPurpose)
                .then(signingHandler -> sign(signingHandler, payload, criticalHeaderClaims),
                        nsse -> {
                            throw sapiJwsSignerException(nsse);
                        }
                );
    }

    /**
     * Heaplet used to create {@link CompactSerializationStringJwsSigner} objects
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
     *     "name": "CompactSerializationMapJwsSigner-RSASSA-PSS",
     *     "type": "com.forgerock.sapi.gateway.jwks.signer.CompactSerializationMapJwsSigner",
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
            return new CompactSerializationStringJwsSigner(secretsProvider, signingKeyId, kid, algorithm);
        }
    }
}
