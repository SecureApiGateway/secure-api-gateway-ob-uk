import groovy.json.JsonSlurper
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.common.JwtReconstruction
import com.securebanking.gateway.dcr.ErrorResponseFactory


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
        try {
            def requestQueryParam = request.getQueryParams().get("request")
            if(!requestQueryParam) {
                return errorResponseFactory.invalidClientMetadataErrorResponse("/authorize endpoint request must include request query parameter")
            } else {
              logger.debug(SCRIPT_NAME + " requestQueryParam is " + requestQueryParam[0])
            }

            authRequestJwt = new JwtReconstruction().reconstructJwt(requestQueryParam[0], SignedJwt.class)
        } catch (e) {
            logger.warn(SCRIPT_NAME + "failed to decode registration request JWT", e)
            return errorResponseFactory.invalidClientMetadataErrorResponse("registration request object is not a valid JWT")
        }
        def authRequestClaims = authRequestJwt.getClaimsSet()

        def scopes = authRequestClaims.getClaim("scope")
        if (!scopes){
            return errorResponseFactory.invalidClientMetadataErrorResponse("Badly formed request jwt: must contain valid scope")
        }
    default:
        logger.debug(SCRIPT_NAME + "Method not supported")
        return next.handle(context, request)
}
