import org.forgerock.http.protocol.*

SCRIPT_NAME = "[GrantTypeVerifier] - "
logger.debug(SCRIPT_NAME + "Running...")

logger.debug(SCRIPT_NAME + "Access token info: " + contexts.oauth2.accessToken.info)
logger.debug(SCRIPT_NAME + "Access token info: " + contexts.oauth2.accessToken.info.grant_type)
def tokenGrantType = contexts.oauth2.accessToken.info.grant_type
if (tokenGrantType == allowedGrantType){
    next.handle(context,request)
}
else {
    def response = new Response(httpCode)
    def message = "invalid_grant_type"
    response.headers['Content-Type'] = "application/json"
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response;
}

