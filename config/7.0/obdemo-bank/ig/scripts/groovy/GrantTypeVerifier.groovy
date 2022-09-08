import org.forgerock.http.protocol.*

SCRIPT_NAME = "[GrantTypeVerifier] - "
logger.debug(SCRIPT_NAME + "Running...")

def tokenGrantType = contexts.oauth2.accessToken.info.grant_type
if (tokenGrantType == allowedGrantType){
    next.handle(context,request)
}
else {
    Response response = new Response(Status.UNAUTHORIZED)
    def message = "invalid_grant_type"
    logger.error(SCRIPT_NAME + message)
    response.headers['Content-Type'] = "application/json"
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response;
}

