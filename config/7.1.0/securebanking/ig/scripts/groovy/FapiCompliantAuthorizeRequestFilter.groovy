import groovy.json.JsonSlurper
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.common.JwtReconstruction
import com.securebanking.gateway.dcr.ErrorResponseFactory
import org.forgerock.http.protocol.Status


def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[FapiCompliantAuthorizeRequestFilter] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")

def errorResponseFactory = new ErrorResponseFactory(SCRIPT_NAME)

def httpMethod = request.method

switch(httpMethod.toUpperCase()){
    case "GET":
        // Parse incoming registration JWT
        logger.debug(SCRIPT_NAME + "Parsing authorize request")
        def authRequestJwt
        
        def requestQueryParam = getQueryParamFromRequest("request")
        if(!requestQueryParam){
            return errorResponseFactory.invalidRedirectUriErrorResponse(SCRIPT_NAME)
        } else {
            logger.debug(SCRIPT_NAME + " requestQueryParam is " + requestQueryParam[0])
        }

        try {
            authRequestJwt = new JwtReconstruction().reconstructJwt(requestQueryParam, SignedJwt.class)
        } catch (e) {
            logger.warn(SCRIPT_NAME + "Badly formed request jwt: failed to decode registration request JWT", e)
            return errorResponseFactory.invalidClientMetadataErrorResponse("registration request object is not a valid JWT")
        }
        def authRequestClaims = authRequestJwt.getClaimsSet()

        def scopes = authRequestClaims.getClaim("scope")
        if (!scopes){
            logger.warn(SCRIPT_NAME + "Badly formed request jwt: Request object has not script claim")
            return redirectWithError("Badly formed request jwt: must contain scope claim")
        }
    default:
        logger.debug(SCRIPT_NAME + "Method not supported")
        return new Response(Status.NOT_FOUND)
}

return next.handle(context, request)

private Response redirectWithError(errorString) {
    def redirect_uri = getQueryParamFromRequest("redirect_uri")
    def state = getQueryParamFromRequest("state")
    if (!state){
        redirect_uri = redirect_uri + "?error=" + "invalid_scope" + "&error_description=" + errorString
    } else {
        redirect_uri = redirect_uri + "?error=" + "invalid_scope" + "&error_description=" + errorString + "&state=" + state
    }
    def response = new Response(Status.FOUND)
    logger.debug(SCRIPT_NAME + " redirect_url is " + url)
    response.getHeaders().add("Location", redirect_uri)
    return response
}

/*
 *  Returns null if the parameter does not exist. Throws IllegalStateException if more than one query parameter with this name exists 
*/
private String getQueryParamFromRequest(paramName) {
    def value = request.getQueryParams().get(paramName)
    if ( !value ) {
        logger.info(SCRIPT_NAME + "No query parameter of name " + paramName + " exists in the request")
        return null
    } else {
        if ( value.size != 1 ) {
            logger.info(SCRIPT_NAME + "There are " + value.size + " values for request parameter " + paramName)
            return null
        } else (
            return value[0]
        )
    }
}
