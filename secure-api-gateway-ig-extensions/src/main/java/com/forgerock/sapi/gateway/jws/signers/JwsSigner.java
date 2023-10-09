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

import java.util.Map;

import org.forgerock.util.promise.Promise;

/**
 * Abstraction of the signature methods to implement a code segment to sign messages.
 * <p>
 *     As result, produce a JWS Compact Serialization from JWS, a string composed of three parts encoded in Base64 Url Safe and separated by a dot ( . ), using
 *     <a href='https://datatracker.ietf.org/doc/html/rfc7159'>JSON-based data structures</a>,
 *     in accordance with: <a href='https://datatracker.ietf.org/doc/html/rfc7515'>RFC7515 JSON Web Signature (JWS)</a>
 * </p>
 * <br/>
 * <h3>Signer</h3>
 * <p>
 * A signer is a functional unity that implements this interface to sign messages.
 * <h4>Signer heap configuration </h4>
 * A signer implementation is pretended to be configured as IG heap object
 * to be used by the filters and/or the IG scripts.
 * <br/>
 * To configure a custom signer implementation as heap object must implement the inner static class Heaplet extending the abstract class {@link org.forgerock.openig.heap.GenericHeaplet}
 * <a href='https://backstage.forgerock.com/docs/ig/7.2/reference/RequiredConfiguration.html#heap-objects'>IG spec reference</a>
 * <br/>
 * Example: com.forgerock.sapi.gateway.jws.signer.CompactSerializationMapJwsSigner
 * </p>
 * <br/>
 * <p>
 * Heaplet implementation
 * <pre>{@code
 * public class CustomSigner implements JwsSigner {
 *
 *     @Override
 *     public Promise<String, SapiJwsSignerException> sign(
 *             final Map<String, Object> payload,
 *             final Map<String, Object> criticalHeaderClaims
 *     ) {
 *         // compute signature
 *     }
 *
 *     public static class Heaplet extends GenericHeaplet {
 *         @Override
 *         public Object create() throws HeapException {
 *             final SecretsProvider secretsProvider = config.get("secretsProvider").required()
 *                     .as(secretsProvider(heap));
 *             final String signingKeyId = config.get("signingKeyId").required().asString();
 *             final String kid = config.get("kid").as(evaluatedWithHeapProperties()).required().asString();
 *             final String algorithm = config.get("algorithm").required().asString();
 *             return new CustomSapiJwsSigner(secretsProvider, signingKeyId, kid, algorithm);
 *         }
 *     }
 * }
 * }</pre>
 * Heap configuration
 * <pre>{@code
 * {
 *     "comment": "Custom payload signer",
 *     "name": "CustomSapiJwsSigner",
 *     "type": "com.forgerock.sapi.gateway.jwks.sign.CustomSapiJwsSigner",
 *     "config": {
 *         "algorithm": string,
 *         "signingKeyId": string,
 *         "kid": string,
 *         "secretsProvider": string (name reference to the secret provided configured in the heap)
 *     }
 * }
 * }
 * </pre>
 * Mandatory fields:
 * <ul>
 *     <li>secretsProvider: The SecretsProvider object to query for the 'signingKeyId' in the keystore</li>
 *     <li>signingKeyId: The signing key id name to identify the private key in the keystore to sign a JWT</li>
 *     <li>kid: Key ID to build the JWT header, used to validate the signature via JWKs</li>
 *     <li>algorithm: The name of the algorithm to use to sign the JWT</li>
 * </ul>
 * <p>
 * <h4>Script filter use</h4>
 * <pre>{@code
 * {
 *   "comment": "Sign messages",
 *   "name": "CustomSigner",
 *   "type": "ScriptableFilter",
 *   "config": {
 *     "type": "application/x-groovy",
 *     "file": "CustomScript.groovy",
 *     "args": {
 *       "signer": "${heap['CustomSigner']}"
 *     }
 *   }
 * }
 * }</pre>
 * </p>
 * <p>
 * <h4>Script example</h4>
 * <pre>{@code
 * signer.sign(payloadMap, critClaims)
 *                 .then(signedJwt -> {
 *                     logger.debug("result {}", signedJwt)
 *                     // process the signed JWT (string)
 *                     return result
 *                 }, sapiJwsSignerException -> { // SapiJwsSignerException handler
 *                     logger.error("Signature fails: {}", sapiJwsSignerException.getMessage())
 *                     response.status = Status.INTERNAL_SERVER_ERROR
 *                     response.entity = "{ \"error\":\"" + sapiJwsSignerException.getMessage() + "\"}"
 *                     return newResultPromise(response)
 *                 })
 * }</pre>
 * </p>
 */
public interface JwsSigner<T> {

    /**
     * Sign the argument Type, that represents a JSON-Based structure, supporting critical header claims.<br/>
     * @param payload              Argument Type that represents the payload to be signed
     * @param criticalHeaderClaims {@link Map}
     * @return a promise of the resulting object.<br/>
     * <ul>Promise:
     *     <li>String: a JWS Compact Serialization from JWS (JSON Web Signature (JWS)) of the task's result</li>
     *     <li>SapiJwsSignerException: The exception thrown by the task if it fails</li>
     * </ul>
     */
    Promise<String, SapiJwsSignerException> sign(final T payload, final Map<String, Object> criticalHeaderClaims);

    default String buildErrorMessage(final String exceptionName, final String customReason) {
        return String.join(
                ": ",
                String.format("Compute signature %s", exceptionName),
                customReason
        );
    }

    default String buildErrorMessage(final Exception exception) {
        return buildErrorMessage(exception.getClass().getSimpleName(), exception.getMessage());
    }

    default String buildErrorMessage(final Exception exception, final String customReason) {
        return buildErrorMessage(exception.getClass().getSimpleName(), customReason);
    }
}
