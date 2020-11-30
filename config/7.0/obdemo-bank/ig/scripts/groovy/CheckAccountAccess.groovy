import org.forgerock.http.protocol.*
import org.forgerock.json.jose.utils.Utils
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.forgerock.json.jose.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt


def error = false


// Look up the intent object

// TODO: get intentId from arg

def intentId = contexts.oauth2.accessToken.info.openbanking_intent_id;

logger.debug("Getting intent from IDM");

Request intentRequest = new Request();

intentRequest.setMethod('GET');
intentRequest.setUri(idmBaseUri + "/openidm/managed/" + objAccountConsent + "/" + intentId)

http.send(intentRequest).then(intentResponse -> {
  intentRequest.close()
  logger.debug("Back from IDM")

  def intentResponseContent = intentResponse.getEntity();
  def intentResponseStatus = intentResponse.getStatus();

  logger.debug("status " + intentResponseStatus);
  logger.debug("entity " + intentResponseContent);

  def intentObj = intentResponseContent.getJson();
  if (intentResponseStatus != Status.OK) {
    logger.error("Failed to get intent from IDM");
    error = true;
  }
  else if (intentObj.Data.Status != "Authorised") {
      logger.error("Not authorised")
      error = true;

  }

  if (!error) {


  }

})

next.handle(context, request)










