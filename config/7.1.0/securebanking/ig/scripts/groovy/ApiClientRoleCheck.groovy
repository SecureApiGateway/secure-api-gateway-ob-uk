import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*

// Check transport certificate for roles appropriate to request
def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ApiClientRoleCheck] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")
logger.debug(SCRIPT_NAME + "Checking certificate roles for {} request",routeArgRole)

if ( !attributes.apiClient ){
  logger.error("FetchApiClientFilter must be run before this script. apiClient needs to exist in the attributes context");
  return new Response(Status.INTERNAL_SERVER_ERROR)
}

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"


List<String> apiClientAllowedRoles = attributes.apiClient.getAllowedRoles()

def roles = attributes.clientCertificate.roles
if (!roles) {
  message = "No roles in apiClient for TPP role check"
  logger.error(SCRIPT_NAME + message)
  response.status = Status.BAD_REQUEST
  response.entity = "{ \"error\":\"" + message + "\"}"
  return response
}


if (!apiClientAllowedRoles.contains(routeArgRole)) {
  message = "client is not authorized to perform role " + routeArgRole
  logger.error(SCRIPT_NAME + message)
  response.status = Status.FORBIDDEN
  response.entity = "{ \"error\":\"" + message + "\"}"
  return response
}
next.handle(context, request)






