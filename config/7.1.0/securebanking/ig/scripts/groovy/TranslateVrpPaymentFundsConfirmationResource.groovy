
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";

SCRIPT_NAME = "[TranslatePaymentFundsConfirmationResource] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")
def domestic_vrp_intent_id = "intentId";
request.uri.path = request.uri.path.replaceFirst("/open-banking/.*","/pisp/domestic-vrp-consents/{{domestic_vrp_intent_id}}/funds-confirmation")
//https://{{MTLS-IG-FQDN}}/rs/open-banking/{{API-VERSION}}/pisp/domestic-vrp-consents/{{domestic_vrp_intent_id}}/funds-confirmation

// Add query parameters
request.uri.rawPath = request.uri.rawPath +
        "/" + attributes.get("accountId") + "?" +
        routeArgAmountQueryParameter + "=" + attributes.get("amount") + "&" +
        routeArgVersionQueryParameter + "=" + attributes.get("version")

logger.debug(SCRIPT_NAME + " The updated raw request uri: " + request.uri.rawPath)
next.handle(context, request)
