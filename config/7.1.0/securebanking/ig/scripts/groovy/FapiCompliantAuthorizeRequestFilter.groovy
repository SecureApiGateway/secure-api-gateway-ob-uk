import groovy.json.JsonSlurper
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.http.protocol.Status

/**
 * This script checks that the call to the /authorize endpoint is
 * correctly formed and valid.
 *
 * Relevant specifications:
 * OAuth 2.0 spec: https://www.rfc-editor.org/rfc/rfc6749#section-4.1
 * FAPI Part 1: https://openid.net/specs/openid-financial-api-part-1-1_0.html#authorization-server
 * FAPI Part 2: https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server
 *
 *
 */

def fapiInteractionId = request.getHeaders().getFirst('x-fapi-interaction-id')
if (fapiInteractionId == null) fapiInteractionId = 'No x-fapi-interaction-id'
SCRIPT_NAME = '[FapiCompliantAuthorizeRequestFilter] (' + fapiInteractionId + ') - '
logger.debug(SCRIPT_NAME + 'Running...')

//def errorResponseFactory = new ErrorResponseFactory(SCRIPT_NAME)

def httpMethod = request.method

switch (httpMethod.toUpperCase()) {
    case 'GET':
    case 'POST':
        // Parse incoming registration JWT
        logger.debug(SCRIPT_NAME + 'Parsing authorize request')

        // From the OAuth 2.0 Spec:
        //   If the request fails due to a missing, invalid, or mismatching
        //   redirection URI, or if the client identifier is missing or invalid,
        //   the authorization server SHOULD inform the resource owner of the
        //   error and MUST NOT automatically redirect the user-agent to the
        //   invalid redirection URI.
        //
        // From the FAPI Part 1 Spec:
        //   Shall only use the parameters included in the signed request object passed via the request or request_uri
        //   parameter
        JwtClaimsSet requestJwtClaimSet = getRequestJtwClaimSet()
        if (!requestJwtClaimSet) {
            return createBadRequestResponse("Request must have a 'request' query parameter the value of which must be "
            + 'a signed jwt')
        }

        String errorMessage = isRequestValidForRedirection(requestJwtClaimSet)
        if (errorMessage != null) {
            logger.info(SCRIPT_NAME + errorMessage)
            return createBadRequestResponse(errorMessage)
        }

        String requiredClaims = ["scope", "state"]
        for (requiredClaim in requiredClaims) {
            if ( !requestJwtHasClaim(requiredClaim, requestJwtClaimSet) ) {
                return logMissingClaimAndGetBadRequestResponse(requiredClaim)
            }    
        }

        // def requestQueryParam = getQueryParamFromRequest("request")
        // if(!requestQueryParam){
        //     return errorResponseFactory.invalidRedirectUriErrorResponse(SCRIPT_NAME)
        // } else {
        //     logger.debug(SCRIPT_NAME + " requestQueryParam is " + requestQueryParam[0])
        // }

        // try {
        //     authRequestJwt = new JwtReconstruction().reconstructJwt(requestQueryParam, SignedJwt.class)
        // } catch (e) {
        //     logger.warn(SCRIPT_NAME + "Badly formed request jwt: failed to decode registration request JWT", e)
        //     return errorResponseFactory.invalidClientMetadataErrorResponse("registration request object is not a valid JWT")
        // }
        // def authRequestClaims = authRequestJwt.getClaimsSet()

        // def scopes = authRequestClaims.getClaim("scope")
        // if (!scopes){
        //     logger.warn(SCRIPT_NAME + "Badly formed request jwt: Request object has not script claim")
        //     return redirectWithError("Badly formed request jwt: must contain scope claim")
        // }
        break
    default:
        logger.debug(SCRIPT_NAME + 'Method not supported')
        return new Response(Status.NOT_FOUND)
}

logger.info("Request is FAPI compliant - calling next.handle")
return next.handle(context, request)


private Boolean requestJwtHasScopeClaim(claimName, requestJwtClaims) {
    return requestJwtClaims.getClaim(claimName)?true:false
}

private Response logMissingClaimAndGetBadRequestResponse(claimName, requestJwtClaims) {
    String errorString = "Invalid Request JWT: must have '" + claimName + "' claim"
    logger.info(SCRIPT_NAME + errorString)
    return createBadRequestResponse(errorString)
}

private Response createBadRequestResponse(errorMessage) {
    def badRequestResponse = new Response(Status.BAD_REQUEST)
    badRequestResponse.setEntity(errorMessage)
    return badRequestResponse
}

private String isRequestValidForRedirection(requestJwtClaims) {
    def redirectUri = requestJwtClaims.getClaim('redirect_uri')

    if (!redirectUri) {
        return 'Invalid Request JWT: must have a redirect_uri claim'
    }

    if (!requestJwtClaims.getClaim('client_id')) {
        return 'Invalid Request JWT: must have a client_id claim'
    }

    return null
}

private JwtClaimsSet getRequestJtwClaimSet() {
    String requestJwtString  = getQueryParamFromRequest('request')
    if (!requestJwtString) {
        logger.info(SCRIPT_NAME + 'BAD_REQUEST: /authorize request must have a request query parameter')
        return null
    }
    try {
        SignedJwt jwt = new JwtReconstruction().reconstructJwt(requestJwtString, SignedJwt.class)
        return jwt.claimSet
    }
    catch (e) {
        logger.info(SCRIPT_NAME + 'BAD_REQUEST: Could not parse request JWT string', e)
        return null
    }
}

// private Response redirectWithError(errorString) {
//     def redirect_uri = getQueryParamFromRequest("redirect_uri")

//     def state = getQueryParamFromRequest("state")
//     if (!state){
//         redirect_uri = redirect_uri + "?error=" + "invalid_scope" + "&error_description=" + errorString
//     } else {
//         redirect_uri = redirect_uri + "?error=" + "invalid_scope" + "&error_description=" + errorString + "&state=" + state
//     }
//     def response = new Response(Status.FOUND)
//     logger.debug(SCRIPT_NAME + " redirect_url is " + url)
//     response.getHeaders().add("Location", redirect_uri)
//     return response
// }

/**
 *  Returns null if the parameter does not exist. Throws IllegalStateException if more than one query parameter with
 *  this name exists
 */
private String getQueryParamFromRequest(paramName) {
    def value = request.getQueryParams().get(paramName)

    if ( !value ) {
        logger.info(SCRIPT_NAME + 'No query parameter of name ' + paramName + ' exists in the request')
        return null
    }

    if ( value.size != 1 ) {
        logger.info(SCRIPT_NAME + 'There are ' + value.size + ' values for request parameter ' + paramName)
        return null
    }

    return value[0]
}
