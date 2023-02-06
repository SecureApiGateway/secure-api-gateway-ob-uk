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
package com.forgerock.sapi.gateway.dcr.request;


import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeNegotiator;
import com.forgerock.sapi.gateway.dcr.common.AcceptHeaderSupplier;
import com.forgerock.sapi.gateway.dcr.common.DCRException;
import com.forgerock.sapi.gateway.dcr.common.ResponseFactory;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.fapi.FAPIUtils;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

/**
 * A filter class that builds a {@code RegistrationRequest} object that contains a {@code SoftwareStatement} and
 * places the {@code RegistrationRequest} on the attributes context
 */
public class RegistrationRequestEntityValidatorFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestEntityValidatorFilter.class);

    private final RegistrationRequestEntitySupplier registrationEntitySupplier;
    private final TrustedDirectoryService trustedDirectoryService;
    private final RegistrationRequest.Builder registrationRequestBuilder;
    private final JwtDecoder jwtDecoder;
    private final AcceptHeaderSupplier acceptHeaderSupplier;
    private final ResponseFactory responseFactory;

    public RegistrationRequestEntityValidatorFilter(RegistrationRequestEntitySupplier registrationEntitySupplier,
            AcceptHeaderSupplier acceptHeaderSupplier, TrustedDirectoryService trustedDirectoryService, 
            RegistrationRequest.Builder registrationRequestBuilder, JwtDecoder jwtDecoder,
            ResponseFactory responseFactory) {
        Reject.ifNull(registrationEntitySupplier, "registrationEntitySupplier must be provided");
        Reject.ifNull(acceptHeaderSupplier, "acceptHeaderSupplier must be provided");
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must be provided");
        Reject.ifNull(registrationRequestBuilder, "registrationRequestBuilder must be provided");
        Reject.ifNull(jwtDecoder, "jwtDecoder must be provided");
        Reject.ifNull(responseFactory, "responseFactory must be provided");
        this.registrationEntitySupplier = registrationEntitySupplier;
        this.acceptHeaderSupplier = acceptHeaderSupplier;
        this.trustedDirectoryService = trustedDirectoryService;
        this.registrationRequestBuilder = registrationRequestBuilder;
        this.jwtDecoder = jwtDecoder;
        this.responseFactory = responseFactory;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final String transactionId = FAPIUtils.getFapiInteractionIdForDisplay(context);
        log.debug("({}) Running RegistrationRequestEntityValidatorFilter", transactionId);
        try {
            String b64EncodedRegistrationRequestEntity = this.registrationEntitySupplier.apply(context, request);
            RegistrationRequest registrationRequest = this.registrationRequestBuilder.build(transactionId,
                    b64EncodedRegistrationRequestEntity);
            context.asContext(AttributesContext.class).getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY,
                    registrationRequest);
            log.info("({}) created context attribute " + RegistrationRequest.REGISTRATION_REQUEST_KEY, transactionId);
            return next.handle(context, request);
        } catch (DCRException exception){
            List<String> acceptHeader = acceptHeaderSupplier.apply(context, request);
            Response response = responseFactory.getResponse(transactionId, acceptHeader, Status.BAD_REQUEST,
                    exception.getErrorFields());
            log.info("({}) Failed to understand the Registration Request body: {}", transactionId,
                    exception.getMessage(), exception);
            return Promises.newResultPromise(response);
        } catch (RuntimeException rte){
            log.warn("({}) caught runtime exception while applying RegistrationRequestEntityValidatorFilter",
                    transactionId, rte);
            List<String> acceptHeader = acceptHeaderSupplier.apply(context, request);
            Map<String, String> errorFields = new LinkedHashMap<>();
            errorFields.put("error", "Server unable to process request");
            errorFields.put("trace_id", transactionId);
            Response response = responseFactory.getResponse(transactionId, acceptHeader,
                    Status.INTERNAL_SERVER_ERROR, errorFields);
            return Promises.newResultPromise(response);
        }
    }

    /**
     * Heaplet is used to get arguments from the IG config and create a RequestAndSsaSignatureValidationFilter
     * on the IG heap.
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));

            final RegistrationRequestEntitySupplier registrationEntitySupplier =
                    new RegistrationRequestEntitySupplier();

            final AcceptHeaderSupplier acceptHeaderSupplier = new AcceptHeaderSupplier();
            final JwtDecoder jwtDecoder = new JwtDecoder();
            final SoftwareStatement.Builder softwareStatementBuilder = new SoftwareStatement.Builder(
                    trustedDirectoryService, jwtDecoder);
            final RegistrationRequest.Builder registrationRequestBuilder = new RegistrationRequest.Builder(
                    softwareStatementBuilder, jwtDecoder);

            final ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory();
            final ContentTypeNegotiator contentTypeNegotiator =
                    new ContentTypeNegotiator(contentTypeFormatterFactory.getSupportedContentTypes());

            final ResponseFactory responseFactory = new ResponseFactory(contentTypeNegotiator,
                    contentTypeFormatterFactory);

            return new RegistrationRequestEntityValidatorFilter( registrationEntitySupplier, acceptHeaderSupplier,
                    trustedDirectoryService, registrationRequestBuilder, jwtDecoder, responseFactory);
        }
    }
}
