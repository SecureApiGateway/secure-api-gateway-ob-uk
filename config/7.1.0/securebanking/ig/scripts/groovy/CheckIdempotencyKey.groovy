/*
 * Script to check the idempotency
 */

import groovy.json.JsonOutput
import java.time.Instant
import java.time.temporal.ChronoUnit

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
        // apiClientId
        def apiClientId = contexts.oauth2.accessToken.info.client_id
        if (apiClientId == null || apiClientId == "") {
            // in case of client credentials grant
            apiClientId = contexts.oauth2.accessToken.info.sub
        }
        // current time to filter the idempotency key expiration time (idempotencyKeyExpiration stored in seconds = creation time + 24hours)
        Instant currentInstantTime = Instant.now()
        logger.debug(SCRIPT_NAME + "apiClientId: " + apiClientId + ", idempotencyKeyExpire: " + idempotencyKeyExpire +", in seconds: " + idempotencyKeyExpire.getEpochSecond())
        // filter by idempotency key, idempotency key expiration time (only valid for 24hours since has been created) and Oauth2ClientId
        def filter = "_queryFilter="+ idempotencyArgFieldToFilter + "+eq+%22" +
                URLEncoder.encode(idempotencyKeyHeaderValue, "UTF-8") + "%22" +
                "+and+" + idempotencyArgExpirationFieldToFilter + "+ge+" + currentInstantTime.getEpochSecond() +
                "+and+Oauth2ClientId+eq+%22" + apiClientId + "%22"

        logger.debug(SCRIPT_NAME + "Filter: " + filter)
        String fields = "_fields=_id,OBIntentObject"
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

/*
curl -v -X GET \
-H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJraWQiOiJrKzN4cXR1NzhMY283aFMraldmUzVnV2ZpNU09IiwiYWxnIjoiUFMyNTYifQ.eyJzdWIiOiJlYzE2YzNkOS1hNDRhLTRhNDMtYmExNS01ZTM2YWEwYTZiNTQiLCJjdHMiOiJPQVVUSDJfU1RBVEVMRVNTX0dSQU5UIiwiYXV0aF9sZXZlbCI6MCwiYXVkaXRUcmFja2luZ0lkIjoiMjlkOTJmZWMtZTM2Ni00YmZlLTg3OGItN2ZhODQ1NDgzOWY3LTI1MDIxIiwic3VibmFtZSI6ImVjMTZjM2Q5LWE0NGEtNGE0My1iYTE1LTVlMzZhYTBhNmI1NCIsImlzcyI6Imh0dHBzOi8vb2JkZW1vLmpvcmdlc2FuY2hlenBlcmV6LmZvcmdlcm9jay5maW5hbmNpYWwvYW0vb2F1dGgyL3JlYWxtcy9yb290L3JlYWxtcy9hbHBoYSIsInRva2VuTmFtZSI6ImFjY2Vzc190b2tlbiIsInRva2VuX3R5cGUiOiJCZWFyZXIiLCJhdXRoR3JhbnRJZCI6ImJYYXFWdHRaTWllQXRzTk1yazk4ZjZSRGRmYyIsImF1ZCI6ImlnLWNsaWVudCIsIm5iZiI6MTY3NjQ1NDQ2MCwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwic2NvcGUiOlsiZnI6aWRtOioiXSwiYXV0aF90aW1lIjoxNjc2NDU0NDYwLCJyZWFsbSI6Ii9hbHBoYSIsImV4cCI6MTY3NjgxNDQ2MCwiaWF0IjoxNjc2NDU0NDYwLCJleHBpcmVzX2luIjozNjAwMDAsImp0aSI6IjZXZGJoMmNFRWUzdGZjbGFsbDNEYUZFR2hBYyJ9.i6ug6ZIqjCv-dzDc5kT2gp-eijaL0_5N8SHVNkFQT6Kr40MyYSDr7dEMt7lkevVdWQNymKhhSo-lk8RMX82oHZOHBFoX14ob4q5284MIRAlyQ4txfSWp-dmgJMn-ha4SP4xOyHcIFjFs1y3s2__j82e3931cJDGm_IkWz4nv4CdhN9voT9GiYVsqBdMW9u-ZniFVYJ6bCljQfd5UnA_JPbJVRvEuAiUg5Ahj3ukspfSpQA0WycUfTBPxRf44B7BxwhILZT0mKIqMcFYbQJYYbnizVIrAeSAIUEAvIjbHUSxO4rjrrVbKGItA8cDqsWV43BhBsjlM5QuK_vsMt2DySw" \
https://iam.jorgesanchezperez.forgerock.financial/openidm/managed/domesticPaymentIntent \
?_queryFilter=IdempotencyKey+eq+%22c7790dd5-e890-45a6-b58b-76a91c2f2a7d%22+and+IdempotencyKeyExpiration+le+1676541807+and+apiClient/oauth2ClientId+eq+%227fdff41b-6013-47ee-a0d4-0baf38f5dd8f%22

curl \
--header "X-OpenIDM-Username: amadmin" \
--header "X-OpenIDM-Password: DiyGGSAB53IUzodjoklGNOkX" \
--header "Accept-API-Version: resource=1.0" \
'https://iam.jorgesanchezperez.forgerock.financial/openidm/managed/user?_queryFilter=userName+eq+"psu4test"'

curl -v -H @header-file "https://iam.jorgesanchezperez.forgerock.financial/openidm/managed/domesticPaymentIntent?_queryFilter=IdempotencyKey+eq+%22c7790dd5-e890-45a6-b58b-76a91c2f2a7d%22+and+*_ref/oauth2ClientId+eq+%22%227fdff41b-6013-47ee-a0d4-0baf38f5dd8f&_prettyPrint=true&_fields=*_ref/oauth2ClientId"
 */