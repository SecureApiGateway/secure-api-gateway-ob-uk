def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ValidateDebtorAccountInRS] (" + fapiInteractionId + ") - "

logger.debug(SCRIPT_NAME + "Running...")
def method = request.method


switch(method.toUpperCase()) {

    case "POST":
        def debtorAccount = request.entity.getJson().Data.Initiation.DebtorAccount
        if(debtorAccount !=null){
            def requestURI = routeArgRsBaseURI + "/backoffice/accounts/search/findByAccountIdentifiers" +
                    "?name=" + debtorAccount.Name + "&identification=" + debtorAccount.Identification +
                    "&schemeName=" + debtorAccount.SchemeName

            logger.debug(SCRIPT_NAME + " findByAccountIdentifiers raw request uri: " + requestURI)
            Request RSRequest = new Request()
            RSRequest.setUri(requestURI)
            RSRequest.setMethod('GET')
            if (request.headers.get("x-fapi-financial-id") != null) {
                RSRequest.putHeaders(request.headers.get("x-fapi-financial-id"))
            }

            return http.send(RSRequest).thenAsync(RSResponse -> {
                def RSResponseStatus = RSResponse.getStatus();
                if (RSResponseStatus != Status.OK) {
                    message = "Failed to find the debtor account by account identifiers"
                    logger.error(SCRIPT_NAME + message)
                    logger.error(SCRIPT_NAME + RSResponse.getEntity().getJson())
                    def response = new Response(RSResponseStatus)
                    response.status = RSResponseStatus
                    response.entity = RSResponse.entity.getJson()
                    return newResultPromise(response)
                }
                if (RSResponse.getEntity().isRawContentEmpty()) {
                    message = "Invalid debtor account, the debtor account provided in the consent does not exist"
                    logger.error(SCRIPT_NAME + message)
                    response = new Response(Status.BAD_REQUEST)
                    response.headers['Content-Type'] = "application/json"
                    response.status = Status.BAD_REQUEST
                    response.entity = "{ \"error\":\"" + message + "\"}"
                    return newResultPromise(response)
                }
                return next.handle(context, request)
            })
        }
    default:
        logger.debug(SCRIPT_NAME + "Skipped")
}

next.handle(context, request)
