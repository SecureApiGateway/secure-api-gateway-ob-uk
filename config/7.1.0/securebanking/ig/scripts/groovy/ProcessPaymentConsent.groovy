import java.text.SimpleDateFormat

/*
 * Script to prepare payment consent
 * Input: OB payment intent JSON
 * Output: IDM create object
 */

SCRIPT_NAME = "[ProcessPaymentConsent] - "
logger.debug(SCRIPT_NAME + "Running...")

def apiClientId = contexts.oauth2.accessToken.info.client_id
if (apiClientId == null || apiClientId == "") {
    // in case of client credentials grant
    apiClientId = contexts.oauth2.accessToken.info.sub
}

def method = request.method

switch(method.toUpperCase()) {

    case "POST":
        paymentIntentData = request.entity.getJson()
        def tz = TimeZone.getTimeZone("UTC");
        def df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(tz);
        def nowAsISO = df.format(new Date());

        def consentId = routeArgConsentIdPrefix + UUID.randomUUID().toString()

        paymentIntentData._id = consentId
        paymentIntentData.Data.ConsentId = consentId
        paymentIntentData.Data.Status = "AwaitingAuthorisation";
        paymentIntentData.Data.CreationDateTime = nowAsISO
        paymentIntentData.Data.StatusUpdateDateTime = nowAsISO
        paymentIntentData.apiClient = [ "_ref" : "managed/" + routeArgObjApiClient + "/" + apiClientId ]

        logger.debug(SCRIPT_NAME + "final json [" + paymentIntentData + "]")
        request.setEntity(paymentIntentData)


        request.uri.path = "/openidm/managed/" + routeArgObjDomesticPaymentConsent
        request.uri.query = "action=create";
        break

    case "GET":
        def consentId = request.uri.path.substring(request.uri.path.lastIndexOf("/") + 1);
        request.uri.path = "/openidm/managed/" + routeArgObjDomesticPaymentConsent + "/" + consentId
        break

    default:
        logger.debug(SCRIPT_NAME + "Method not supported")

}

next.handle(context, request)

