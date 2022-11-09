import java.security.SignatureException
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.http.protocol.Status;
import com.forgerock.securebanking.uk.gateway.jws.RsaJwtSignatureValidator
import java.net.URI;

SCRIPT_NAME = "[SSAVerifier] - "
logger.debug(SCRIPT_NAME + "Running...")

def verifySignature(signedJwt,jwksJson) {
    def jwks = JWKSet.parse(jwksJson);
    try {
        new RsaJwtSignatureValidator().validateSignature(signedJwt, jwks)
        return true
    } catch (SignatureException se) {
        logger.error("jwt signature validation failed", se)
        return false
    }
}

def errorResponse(httpCode, message) {
    logger.error(SCRIPT_NAME + "Returning error " + httpCode + ": " + message);
    def response = new Response(httpCode)
    response.headers['Content-Type'] = "application/json"
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response;
}

def method = request.method

switch(method.toUpperCase()) {

    case "POST":

        if (!attributes.registrationJWTs) {
            return(errorResponse(Status.UNAUTHORIZED,"No registration JWT"));
        }

        def ssaJwt = attributes.registrationJWTs.ssaJwt;

        if (!ssaJwt) {
            return(errorResponse(Status.UNAUTHORIZED,"No SSA JWT"));
        }

        if (!routeArgSSAIssuerJwksUrls) {
            return(errorResponse(Status.INTERNAL_SERVER_ERROR,"No configured JWKS URIs"));
        }

        def ssaClaims = ssaJwt.getClaimsSet();

        def ssaIssuer = ssaClaims.getIssuer();

        if (!ssaIssuer) {
            return(errorResponse(Status.UNAUTHORIZED,"SSA has no issuer"));
        }

        def ssaJwksUrl = routeArgSSAIssuerJwksUrls[ssaIssuer];

        if (!ssaJwksUrl) {
            return(errorResponse(Status.UNAUTHORIZED,"Unknown SSA issuer: " + ssaIssuer));
        }

        def ssaJwksUri = null;

        try {
            ssaJwksUri = new URI(ssaJwksUrl);
        }
        catch (e) {
            return(errorResponse(Status.INTERNAL_SERVER_ERROR,"Error parsing JWKS URL " + ssaJwksUrl + "(" + e + ")"));
        }

        logger.debug(SCRIPT_NAME + "Validating SSA JWT - Issuer {}, JWKS URI {}",ssaIssuer,ssaJwksUrl);

        Request jwksRequest = new Request();


        jwksRequest.setMethod('GET');
        jwksRequest.setUri(ssaJwksUrl);
        // jwksRequest.getHeaders().add("Host",ssaJwksUri.getHost());


        http.send(jwksRequest).then(jwksResponse -> {

            jwksRequest.close();
            logger.debug(SCRIPT_NAME + "Back from JWKS URI");
            def jwksResponseContent = jwksResponse.getEntity().getString();
            def jwksResponseStatus = jwksResponse.getStatus();

            logger.debug(SCRIPT_NAME + "status " + jwksResponseStatus);
            logger.debug(SCRIPT_NAME + "entity " + jwksResponseContent);

            if (jwksResponseStatus != Status.OK) {
                return(errorResponse(Status.UNAUTHORIZED,"Bad response from JWKS URI " + jwksResponseStatus));
            }
            else if (!verifySignature(ssaJwt,jwksResponseContent)) {
                return(errorResponse(Status.UNAUTHORIZED,"Signature not verified"));
            }

            return null;
        }).thenAsync (error -> {
            if (error) {
                // TODO: This doesn't work - get cast error from Response to Promise
                logger.error(SCRIPT_NAME + "Sending back error response");
                return error;
            }
            next.handle(context, request);
        });
        break

    case "DELETE":
        break
    default:
        logger.debug(SCRIPT_NAME + "Method not supported")

}


next.handle(context, request)

