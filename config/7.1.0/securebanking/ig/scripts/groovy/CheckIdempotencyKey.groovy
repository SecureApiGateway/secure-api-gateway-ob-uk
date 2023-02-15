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
        // calculate the expired time for idempotency key (current date time + 24 hours)
        Instant idempotencyKeyExpire = Instant.now().plus(24, ChronoUnit.HOURS)
        logger.debug(SCRIPT_NAME + "apiClientId: " + apiClientId + ", idempotencyKeyExpire: " + idempotencyKeyExpire +", in seconds: " + idempotencyKeyExpire.getEpochSecond())
        def filter = "_queryFilter="+ idempotencyArgFieldToFilter + "+eq+%22" +
                URLEncoder.encode(idempotencyKeyHeaderValue, "UTF-8") + "%22" +
                "+and+IdempotencyKeyExpiration+le+" + idempotencyKeyExpire.getEpochSecond() +
                "+and+oauth2ClientId+eq+%22" + apiClientId + "%22"

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

/*
curl -v -X GET -H "X-OpenIDM-Username: amadmin" -H "X-OpenIDM-Password: xRYlpBo0tJl4jcqsE3J8G1US" \
-H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJraWQiOiJjZ0Zxb1hCY25yK1RwcU5ORFJMVkhaYXBQQU09IiwiYWxnIjoiUFMyNTYifQ.eyJzdWIiOiJhOGNiMzA1ZC04ZmU3LTQ5NzktYjJmMy0xZWJkYzU3NDQyOGYiLCJjdHMiOiJPQVVUSDJfU1RBVEVMRVNTX0dSQU5UIiwiYXV0aF9sZXZlbCI6MCwiYXVkaXRUcmFja2luZ0lkIjoiMzAyZjhjMGYtY2VkNS00OGRjLTljNDAtMzY4NzEzNWFhNTFlLTIzOTA0MCIsInN1Ym5hbWUiOiJhOGNiMzA1ZC04ZmU3LTQ5NzktYjJmMy0xZWJkYzU3NDQyOGYiLCJpc3MiOiJodHRwczovL29iZGVtby5qb3JnZXNhbmNoZXpwZXJlei5mb3JnZXJvY2suZmluYW5jaWFsL2FtL29hdXRoMi9yZWFsbXMvcm9vdC9yZWFsbXMvYWxwaGEiLCJ0b2tlbk5hbWUiOiJhY2Nlc3NfdG9rZW4iLCJ0b2tlbl90eXBlIjoiQmVhcmVyIiwiYXV0aEdyYW50SWQiOiJuSW9WRGZ4MzNPNWMtcnJGQzhqTkFXSVpLdlkiLCJhdWQiOiJpZy1jbGllbnQiLCJuYmYiOjE2NzYzOTE5OTAsImdyYW50X3R5cGUiOiJwYXNzd29yZCIsInNjb3BlIjpbImZyOmlkbToqIl0sImF1dGhfdGltZSI6MTY3NjM5MTk5MCwicmVhbG0iOiIvYWxwaGEiLCJleHAiOjE2NzY3NTE5OTAsImlhdCI6MTY3NjM5MTk5MCwiZXhwaXJlc19pbiI6MzYwMDAwLCJqdGkiOiJZdzFNS2xTd0QxMFk3ci1vaEZ3TmdTLXI3ZVUifQ.5zFi-cF22Yv0KFaMDWw-TorYPayx9qIJ7e0o83tJPP6ifboEt9K_6qWmlnHZi3Zh5gN82qEwKRuu3TdyhM4H8yhJD4tGZHZ-HhxtYcKrA8M6PHrILroh9Plqvdp0LkH6v1Bu2CvIV4zEt8IKNYuJGa3ZtkZv_Fn02bjFdux7j5TcT5XNv1Hg4QOGtLXGeMB8tPHkyOK1h1WlK_Kpje91m8Pmiqix7Fke0_KtF_RIrfFARtM3jL91-5mmJPEyoms7ALfFfH1_Kr_lsGWM4sBr9mVJwtMS-3TvA-QCR0IKKu2OXEUy9hKG7TUjSm2r6YIHCeLzhGnlTpwFf4XtewJwgA" \
https://iam.jorgesanchezperez.forgerock.financial/openidm/managed/domesticPaymentIntent?_queryFilter=IdempotencyKey+eq+%22c7790dd5-e890-45a6-b58b-76a91c2f2a7d%22+and+IdempotencyKeyExpiration+le+1676480666+and+apiClient/_id+eq+%220e2738b6-ab92-4156-8327-066ad8ffb5aa%22
 */