/*
 * Script to check the idempotency
 */

import groovy.json.JsonOutput

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[CheckIdempotencyKey] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

// response object
responseCheck = new Response(Status.OK)
responseCheck.headers['Content-Type'] = "application/json"

String idempotencyKeyHeaderValue = request.getHeaders().getFirst("x-idempotency-key")
logger.debug(SCRIPT_NAME + " idempotency key: " + idempotencyKeyHeaderValue)

def method = request.method
f550510ee57facefdd456df8e7beb218f550510
// Only check when post
switch (method.toUpperCase()) {
    case "POST":
        if (idempotencyKeyHeaderValue == null) {
            message = "Failed to get create the resource, 'x-idempotency-key' header / value expected"
            logger.error(SCRIPT_NAME + message)
            responseCheck.status = Status.BAD_REQUEST
            responseCheck.entity = "{ \"error\":\"" + message + "\"}"
            return responseCheck
            // the idempotencyKey size must be at most 40 characters
        } else if(idempotencyKeyHeaderValue.length() > 39){
            message = "Failed to get create the resource, 'x-idempotency-key' size exceeded, the size must be at most 40 characters"
            logger.error(SCRIPT_NAME + message)
            responseCheck.status = Status.BAD_REQUEST
            responseCheck.entity = "{ \"error\":\"" + message + "\"}"
            return responseCheck
        }

        // prepare the request filter
        def filter = "_queryFilter="+ idempotencyArgFieldToFilter + "+eq+%22" + URLEncoder.encode(idempotencyKeyHeaderValue, "UTF-8") + "%22"
        logger.debug(SCRIPT_NAME + "Filter: " + filter)
        String fields = "_fields=_id,OBIntentObject,user/_id,accounts,account,apiClient/oauth2ClientId,apiClient/name,AccountId,IdempotencyKey"
        def requestUri = routeArgIdmBaseUri + "/openidm/managed/" + intentArgObject + "?" + filter + "&" + fields
        logger.debug(SCRIPT_NAME + "Request URI: " + requestUri)

        // build the request
        Request intentRequest = new Request();
        intentRequest.setUri(requestUri);
        intentRequest.setMethod('GET');
        return http.send(intentRequest).thenAsync(intentResponse -> {
            intentRequest.close()
            logger.debug(SCRIPT_NAME + "Back from IDM")
            def intentResponseStatus = intentResponse.getStatus()
            if (intentResponseStatus != Status.OK) {
                message = "Failed to validate idempotent request"
                logger.error(SCRIPT_NAME + message)
                response.status = intentResponseStatus
                response.entity = "{ \"error\":\"" + message + "\"}"
                return response
            }

            def intentResponseResult = intentResponse.entity.getJson().result
            if (!intentResponseResult.isEmpty()) {
                // For file submission the response needs to be Ok with empty entity
                if(idempotencyArgFieldToFilter == "IdempotencyKeyFile") {
                    intentResponse.status = Status.OK
                    intentResponse.entity = ""
                    return newResultPromise(intentResponse)
                }
                intentResponse.status = Status.CREATED
                intentResponse.entity = JsonOutput.toJson(intentResponseResult[0].get("OBIntentObject"))
                return newResultPromise(intentResponse)
            }
            return next.handle(context, request)
        })
}
next.handle(context, request)