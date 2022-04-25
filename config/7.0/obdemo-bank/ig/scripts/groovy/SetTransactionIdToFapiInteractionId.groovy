import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import groovy.json.JsonSlurper


/*
 * Script to set the x-fapi-interaction-id on the request so that it can be forwarded to backend services.
 *
 * Ensure response header has interaction ID
 *
 * Ensure that response body is OB compliant on error
 *
 * If not HTTP error response, then allow through
 * If HTTP error response with OB error message (i.e. from RS), then allow through
 * If HTTP error response and OB error in shared state (i.e. from IG), then set response entity to OB error
 * If HTTP error response with no OB error in shared state, set response body to generic OB error
 */

String FAPI_INTERACTION_ID_HEADER_NAME = "x-fapi-interaction-id"
String FORGEROCK_TRANSACTION_ID_HEADER_NAME = "x-forgerock-transactionid"
String REQUEST_ID_HEADER_NAME = "X-Request-ID"


String val = null
inboundValues = request.headers.get(FAPI_INTERACTION_ID_HEADER_NAME)
if (inboundValues == null) {
    logger.warn("SetTransactionIdToFapiInteractionId: no x-fapi-interaction-id set!!!")
    logger.debug("SetTransactionIdToFapiInteractionId: No inbound x-fapi-interaction-id header value - creating one")
    val = UUID.randomUUID().toString();
    request.headers.add(FAPI_INTERACTION_ID_HEADER_NAME, val)
    logger.debug("SetTransactionIdToFapiInteractionId: x-fapi-interaction-id for {} request to {} is {}", request.method, request.uri, val)
} else {
    val = inboundValues.firstValue;
    logger.debug("SetTransactionIdToFapiInteractionId: x-fapi-interaction-id supplied for {} request to {} is {}", request.method, request.uri, val)
}

request.headers.add(FORGEROCK_TRANSACTION_ID_HEADER_NAME, val)
request.headers.add(REQUEST_ID_HEADER_NAME, val)

next.handle(context, request)









