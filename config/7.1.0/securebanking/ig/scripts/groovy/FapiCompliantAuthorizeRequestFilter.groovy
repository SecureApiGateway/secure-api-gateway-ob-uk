import groovy.json.JsonSlurper
import com.forgerock.securebanking.uk.gateway.jwks.*
import java.security.SignatureException
import com.nimbusds.jose.jwk.RSAKey;
import com.securebanking.gateway.dcr.ErrorResponseFactory
import static org.forgerock.util.promise.Promises.newResultPromise


def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ProcessRegistration] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")

def errorResponseFactory = new ErrorResponseFactory(SCRIPT_NAME)

def httpMethod = request.method

switch(method.toUpperCase()){
    case "GET":
        // Parse incoming registration JWT
        logger.debug(SCRIPT_NAME + "Parsing authorize request");
        def authRequestJwt
        try {
            authRequestJwt = new JwtReconstruction().reconstructJwt(request.getQueryParams().get("request"), SignedJwt.class)
        } catch (e) {
            logger.warn(SCRIPT_NAME + "failed to decode registration request JWT", e)
            return errorResponseFactory.invalidClientMetadataErrorResponse("registration request object is not a valid JWT")
        }
        def authRequestClaims = authRequestJwt.getClaimsSet()

        def scopes = authRequestClaims.getClaim("scope")
        if (!scopes){
            return errorResponseFactory.invalidClientMetadataErrorResponse("Badly formed request jwt: must contain valid scope")
        }

}