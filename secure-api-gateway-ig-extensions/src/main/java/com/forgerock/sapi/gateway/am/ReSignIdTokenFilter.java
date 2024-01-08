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
package com.forgerock.sapi.gateway.am;

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.IdTokenAccessorLocator.IdTokenAccessor;

/**
 * This filter aims to fix an issue in AM relating to signing of the id_token JWTs.
 * <p>
 * Certain use cases, such as OpenBanking UK, require keys from an external (to AM) jwks_uri be used to sign JWTs.
 * AM can be configured to use these private keys via secret mappings, but there is an issue with how AM determines
 * the kid value to use in the JWS header.
 * For the OpenBanking UK case, the kid value does not match what is expected which means that clients will not trust
 * id_token values return by AM.
 * <p>
 * To resolve this issue, this filter decodes the id_token returned by AM and creates a new one with the correct kid,
 * it is then signed using a key that must be configured to match the expected key in the external jwks_uri
 * <p>
 * There is a ticket open with AM to fix this issue: https://bugster.forgerock.org/jira/browse/OPENAM-15617
 */
public class ReSignIdTokenFilter implements Filter {

    private static final String ID_TOKEN_FIELD_NAME = "id_token";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Takes a JWT as input, verifies the signature and re-signs it with the configured private key.
     */
    private final JwtReSigner jwtReSigner;

    /**
     * Locator of an {@link IdTokenAccessor} for a given Response.
     * <p>
     * The filter logic uses this to get and set the id_token value in the Response. Different implementations are
     * available, allowing this filter to be used to process responses from different AM endpoints.
     */
    private final IdTokenAccessorLocator idTokenAccessorLocator;

    public ReSignIdTokenFilter(JwtReSigner jwtReSigner, IdTokenAccessorLocator idTokenAccessorLocator) {
        Reject.ifNull(jwtReSigner, "jwtReSigner must be supplied");
        Reject.ifNull(idTokenAccessorLocator, "idTokenLocator must be supplied");
        this.jwtReSigner = jwtReSigner;
        this.idTokenAccessorLocator = idTokenAccessorLocator;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        return handler.handle(context, request).thenAsync(response -> {
            // Allow AM errors to pass through
            if (!response.getStatus().isSuccessful() && !response.getStatus().isRedirection()) {
                return newResultPromise(response);
            } else {
                return idTokenAccessorLocator.createIdTokenAccessor(response).thenAsync(optionalIdTokenAccessor -> {
                    if (optionalIdTokenAccessor.isEmpty()) {
                        logger.debug("No id_token found in response, doing nothing.");
                        return newResultPromise(response);
                    }
                    final IdTokenAccessor idTokenAccessor = optionalIdTokenAccessor.get();
                    final String idTokenJwtString = idTokenAccessor.getIdToken();
                    logger.debug("Located id_token: {}", idTokenJwtString);

                    return jwtReSigner.reSignJwt(idTokenJwtString).then(resignedIdTokenJwtString -> {
                        idTokenAccessor.setIdToken(resignedIdTokenJwtString);
                        return response;
                    }, ex -> new Response(Status.INTERNAL_SERVER_ERROR));
                }, ex -> {
                    logger.error("Failed to re-sign id_token JWT", ex);
                    return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                });
            }
        });
    }

    /**
     * Locator of IdTokenAccessors for a particular Response object.
     */
    interface IdTokenAccessorLocator {

        /**
         * Represents a getter/setter for an id_token, which allows the calling class to be agnostic of the actual
         * location of the id_token within the Response object.
         */
        class IdTokenAccessor {

            private final String idToken;
            private final Consumer<String> idTokenSetter;

            private IdTokenAccessor(String idToken, Consumer<String> idTokenSetter) {
                this.idToken = idToken;
                this.idTokenSetter = idTokenSetter;
            }

            public String getIdToken() {
                return idToken;
            }

            public void setIdToken(String idToken) {
                idTokenSetter.accept(idToken);
            }
        }

        /**
         * @param response Response object to create the IdTokenAccessor for
         * @return Optional<IdTokenAccessor> an IdTokenAccessor which is capable of getting and setting the id_token,
     *                                       or an empty Optional if no id_token can be located
         */
        Promise<Optional<IdTokenAccessor>, Exception> createIdTokenAccessor(Response response);

    }

    /**
     * IdTokenLocator implementation that works with /access_token responses:
     * https://backstage.forgerock.com/docs/am/7.2/oauth2-guide/oauth2-access_token-endpoint.html
     * <p>
     * The id_token field is optional in the json response, only being returned if the openid scope was requested.
     */
    static class AccessTokenEndpointIdTokenAccessorLocator implements IdTokenAccessorLocator {

        private final Logger logger = LoggerFactory.getLogger(getClass());

        @Override
        public Promise<Optional<IdTokenAccessor>, Exception> createIdTokenAccessor(Response response) {
            return response.getEntity().getJsonAsync().thenAsync(jsonObj -> {
                logger.debug("Locating id_token in response json");
                final JsonValue json = json(jsonObj);
                final JsonValue idTokenValue = json.get(ID_TOKEN_FIELD_NAME);
                if (idTokenValue.isNull() || !idTokenValue.isString()) {
                    logger.debug("No id_token in response json");
                    return newResultPromise(Optional.empty());
                }
                final String idToken = idTokenValue.asString();
                return newResultPromise(Optional.of(new IdTokenAccessor(idToken, (updatedIdToken) -> {
                    // Assumption that json contents will not change between call to findIdToken and call to set the updated token
                    json.put("id_token", updatedIdToken);
                    response.getEntity().setJson(json);
                })));
            }, Promises::newExceptionPromise);
        }
    }


    /**
     * IdTokenLocator implementation that works with the /authorize endpoint:
     * https://backstage.forgerock.com/docs/am/7.2/oauth2-guide/oauth2-authorize-endpoint.html
     * <p>
     * For this endpoint, the location of the token depends on the response_mode sent in the request (or the default
     * if none was supplied). Currently, the implementation assumes that the token is in the URI fragment of the
     * location header as per the OIDC Hybrid flow:
     * https://backstage.forgerock.com/docs/am/7.2/oidc1-guide/openid-connect-hybrid-flow.html
     * <p>
     * Further work is required to support JARM (response_mode=jwt), as the jwt containing the id_token would also
     * need to be re-signed.
     */
    static class AuthorizeEndpointIdTokenAccessorLocator implements IdTokenAccessorLocator {

        private final Logger logger = LoggerFactory.getLogger(getClass());

        @Override
        public Promise<Optional<IdTokenAccessor>, Exception> createIdTokenAccessor(Response response) {
            try {
                final Optional<MutableUri> optionalLocationUri = getLocationHeader(response);
                if (optionalLocationUri.isEmpty()) {
                    logger.debug("No location header found, skipping");
                    return newResultPromise(Optional.empty());
                }
                final MutableUri locationUri = optionalLocationUri.get();
                logger.debug("Locating id_token in response location header: {}", locationUri);
                final String fragment = locationUri.getFragment();
                if (fragment == null) {
                    final String query = locationUri.getQuery();
                    if (query == null) {
                        return newResultPromise(Optional.empty());
                    } else {
                        return buildIdTokenQueryAccessor(response, locationUri, query);
                    }
                }
                return buildIdTokenFragmentAccessor(response, locationUri, fragment);
            } catch (URISyntaxException e) {
                return newExceptionPromise(e);
            }
        }

        private Promise<Optional<IdTokenAccessor>, Exception> buildIdTokenFragmentAccessor(Response response,
                                                                                           MutableUri locationUri,
                                                                                           String fragment) {
            return buildFormAccessor(response, fragment, (fragmentOrQuery) -> {
                try {
                    locationUri.setFragment(fragmentOrQuery);
                    return locationUri;
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        private Promise<Optional<IdTokenAccessor>, Exception> buildIdTokenQueryAccessor(Response response,
                                                                                        MutableUri locationUri,
                                                                                        String query) {
            return buildFormAccessor(response, query, (fragmentOrQuery) -> {
                try {
                    locationUri.setQuery(fragmentOrQuery);
                    return locationUri;
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        private Promise<Optional<IdTokenAccessor>, Exception> buildFormAccessor(Response response, String fragmentOrQuery,
                                                                                Function<String, MutableUri> uriUpdater) {
            // fragments and query strings have the same format, both are parsable by the fromQueryString method
            final Form form = new Form().fromQueryString(fragmentOrQuery);
            final String idToken = form.getFirst(ID_TOKEN_FIELD_NAME);
            if (idToken == null) {
                logger.debug("No id_token found in location header");
                return newResultPromise(Optional.empty());
            }
            final Consumer<String> idTokenSetter = updatedIdToken -> {
                form.replace(ID_TOKEN_FIELD_NAME, List.of(updatedIdToken));
                final MutableUri updatedUri = uriUpdater.apply(form.toQueryString());
                response.getHeaders().replace("location", updatedUri.toString());
            };
            return newResultPromise(Optional.of(new IdTokenAccessor(idToken, idTokenSetter)));
        }

        private static Optional<MutableUri> getLocationHeader(Response response) throws URISyntaxException {
            final String locationHeader = response.getHeaders().getFirst("location");
            if (locationHeader == null) {
                return Optional.empty();
            }
            return Optional.of(MutableUri.uri(locationHeader));
        }
    }

    /**
     * Heaplet which creates {@link ReSignIdTokenFilter} objects.
     * <p>
     * Configuration:
     * <ul>
     *     <li>endpointType which endpoint is this filter being used with, valid values: [access_token, authorize]</li>
     *     <li>jwtReSigner name of a {@link JwtReSigner} available on the heap, used to validate in the incoming JWT
     *         and produce the new JWT signed with the correct key and keyId.</li>
     * </ul>
     * <p>
     * <pre>{@code
     * Example config:
     * {
     *   "name": "ReSignIdTokenFilter",
     *   "type": "ReSignIdTokenFilter",
     *   "comment": "Re-sign the id_token returned by AM to fix OB keyId issue",
     *   "config": {
     *     "endpointType": "access_token",
     *     "jwtReSigner": "jwtReSigner"
     *   }
     * }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {
        private static final Map<String, Supplier<IdTokenAccessorLocator>> ENDPOINT_TYPE_REGISTRY = new HashMap<>();

        static {
            ENDPOINT_TYPE_REGISTRY.put("authorize", AuthorizeEndpointIdTokenAccessorLocator::new);
            ENDPOINT_TYPE_REGISTRY.put("access_token", AccessTokenEndpointIdTokenAccessorLocator::new);
        }

        @Override
        public Object create() throws HeapException {

            final String endpointType = config.get("endpointType").asString();
            final Supplier<IdTokenAccessorLocator> idTokenAccessorLocatorSupplier = ENDPOINT_TYPE_REGISTRY.get(endpointType);
            Reject.ifNull(idTokenAccessorLocatorSupplier,
                    "Unsupported endpointType: " + endpointType + ", specify one of: " + ENDPOINT_TYPE_REGISTRY.keySet());

            final JwtReSigner jwtReSigner = config.get("jwtReSigner").as(requiredHeapObject(heap, JwtReSigner.class));

            return new ReSignIdTokenFilter(jwtReSigner, idTokenAccessorLocatorSupplier.get());
        }
    }
}
