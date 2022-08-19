SCRIPT_NAME = "[TranslatePaymentFundsConfirmationResource] - "
logger.debug(SCRIPT_NAME + "Running...")

request.uri.path = request.uri.path.replaceFirst("/open-banking/.*","/backoffice/payment-funds-confirmation")

def JsonValue intentObject = attributes.get("intentJsonObject");

logger.debug(SCRIPT_NAME + " The intent object to use for backoffice: " + intentObject);

// Add query parameters
request.uri.rawPath = request.uri.rawPath +
        "/" + attributes.get("accountId") + "?" +
        routeArgVersionQueryParameter + "=" + attributes.get("version")
logger.debug(SCRIPT_NAME + " The updated raw request uri: " + request.uri.rawPath)

//changing method to POST
request.setMethod("POST");
request.setEntity(intentObject);

next.handle(context, request)
