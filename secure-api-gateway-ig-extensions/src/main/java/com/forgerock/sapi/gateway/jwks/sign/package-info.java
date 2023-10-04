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

/**
 * com.forgerock.sapi.gateway.jwks.sign <br/>
 * <h1>Overview</h1>
 * Sometimes a specification require sign messages as JSON Web Signatures (JWS) to met Non-repudiation requirements,
 * JSON Web Signature (JWS) represents the payload of a JWS as a base64url-encoded value and uses this value in the JWS Signature computation.
 * <p>
 *     <em><a href='https://datatracker.ietf.org/doc/html/rfc7515'>RFC7515 JSON Web Signature (JWS)</a></em>
 * </p>
 * <h2>Package Specification</h2>
 * <p>
 * Provides interfaces to implement custom signers to sign messages.<br/>
 * Provides Default signer implementation to compute signatures used in filters of provided routes.
 * </p>
 * <h3>Interfaces</h3>
 * <ul>
 *     <li>A signer interface {@link com.forgerock.sapi.gateway.jwks.sign.SapiJwsSigner}</li>
 *     <li>A signer result interface {@link com.forgerock.sapi.gateway.jwks.sign.SapiJwsSignerResult}</li>
 * </ul>
 * <h3><em>Default</em> implementations</h3>
 * <ul>
 *     <li>A Default signer implementation {@link com.forgerock.sapi.gateway.jwks.sign.DefaultSapiJwsSigner}</li>
 *     <li>A Default Result signer implementation {@link com.forgerock.sapi.gateway.jwks.sign.DefaultSapiJwsSignerResult}</li>
 * </ul>
 * <h3><em>Exceptions</h3>
 * <ul>
 *     <li>{@link com.forgerock.sapi.gateway.jwks.sign.SapiJwsSignerException}</li>
 * </ul>
 * <h2>Configuration</h2>
 * <h4>Introduction</h4>
 * In terms of Identity Gateway (IG) a heaplet creates and initializes an object that is stored in a heap.
 * <ul>
 *     <li>A heaplet can retrieve objects it depends on from the heap.</li>
 *     <li>A heap is a collection of associated objects created and initialized by heaplet objects.</li>
 *     <li>All configurable objects in IG are heap objects.</li>
 *     <li>The heap configuration is included as an object in admin.json and config.json.</li>
 * </ul>
 * <p>
 * <em><a href='https://backstage.forgerock.com/docs/ig/7.2/reference/RequiredConfiguration.html#heap-objects'>IG spec reference</a></em>
 * </p>
 * <br/>
 * A signer implementation could be used as heaplet object across filters or another heaplets. <br/>
 * <h4>Default Signer Heaplet configuration example</h4>
 *  Heaplet used to create {@link com.forgerock.sapi.gateway.jwks.sign.DefaultSapiJwsSigner} objects
 *  <p/>
 *  Mandatory fields:
 *  <ul>
 *      <li>secretsProvider: The SecretsProvider object to query for the 'signingKeyId' in the keystore</li>
 *      <li>signingKeyId: The signing key id name to identify the private key in the keystore to sign a JWT</li>
 *      <li>kid: Key ID to build the JWT header, used to validate the signature via JWKs</li>
 *      <li>algorithm: The name of the algorithm to use to sign the JWT</li>
 *  </ul>
 *  Example config:
 *  <pre>{@code
 *  {
 *      "comment": "Default payload signer",
 *      "name": "DefaultSapiJwsSigner-RSASSA-PSS",
 *      "type": "com.forgerock.sapi.gateway.jwks.sign.DefaultSapiJwsSigner",
 *      "config": {
 *          "algorithm": "PS256",
 *          "signingKeyId": "jwt.signer",
 *          "kid": "&{ig.ob.aspsp.signing.kid}",
 *          "secretsProvider": "SecretsProvider-ASPSP"
 *      }
 *  }
 *  }</pre>
 * <h4>Use example of heaplet</h4>
 * <pre>{@code
 * {
 *   "comment": "Sign events from the RS response",
 *   "name": "SignEvents",
 *   "type": "ScriptableFilter",
 *   "config": {
 *     "type": "application/x-groovy",
 *     "file": "SignEventsResponse.groovy",
 *     "args": {
 *       "signer": "${heap['DefaultSapiJwsSigner-RSASSA-PSS']}",
 *       "aspspOrgId": "&{ob.aspsp.org.id}"
 *     }
 *   }
 * }
 * }</pre>
 *
 * @author	  Jorge Sanchez Perez
 * @since	  2.0
 */
package com.forgerock.sapi.gateway.jwks.sign;