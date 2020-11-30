import java.text.SimpleDateFormat

/*
 * Script to prepare account access consent
 * Input: OB account access intent JSON
 * Output: IDM create object
 */

// TODO: figure out why we can't pass the tpp id in as an arg from the route

def tppId = contexts.oauth2.accessToken.info.client_id

/*

Request tppRequest = new Request();

tppRequest.setMethod('GET');
tppRequest.setUri(idmBaseUri + "/openidm/managed/" + objTpp + "?_queryFilter=/identifier+eq+" + tppId)

http.send(tppRequest).then(tppResponse -> {
        ssaRequest.close()
        logger.debug("Back from IDM")

  def tppResponseContent = ssaResponse.getEntity();
  def tppResponseStatus = ssaResponse.getStatus();

  logger.debug("status " + tppResponseStatus);
  logger.debug("entity " + tppResponseContent);

  if (tppResponseStatus != Status.OK) {
      logger.error("Failed to get response from IDM");
      error = true;
  }
  else {

      def ssaObj = ssaResponse.entity.getJson();

      def ssaId = ssaObj._id
  }
*/

accountIntentData = request.entity.getJson()

def tz = TimeZone.getTimeZone("UTC");
def df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'+00:00'");
df.setTimeZone(tz);
def nowAsISO = df.format(new Date());

accountIntentData.Data.Status = "AwaitingAuthorisation";
accountIntentData.Data.CreationDateTime = nowAsISO
accountIntentData.Data.StatusUpdateDateTime = nowAsISO
accountIntentData.Tpp = [ "_ref" : "managed/" + objTpp + "/" + tppId ]

logger.debug("final json [" + accountIntentData + "]")
request.setEntity(accountIntentData)


request.uri.path = "/openidm/managed/" + objAccountConsent
request.uri.query = "action=create";

next.handle(context, request)






