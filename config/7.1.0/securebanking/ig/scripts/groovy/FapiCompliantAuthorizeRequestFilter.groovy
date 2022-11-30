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

        Response errorResponse = isRequestValidForRedirection(requestJwtClaimSet)
        if (errorResponse) {
            return errorResponse
        }

        // ToDo - any failures of these tests should really result in errors being sent to the redirect URI, but we 
        // haven't yet validated the requestJwt so we can't truly trust it. We leave AM to do the JWT validation. 
        // The OAuth spec says this about errors:
        //   If the resource owner denies the access request or if the request
        //   fails for reasons other than a missing or invalid redirection URI,
        //   the authorization server informs the client by adding the following
        //   parameters to the query component of the redirection URI using the
        //   "application/x-www-form-urlencoded" format, per Appendix B:
        // However, the FAPI Advanced Part 1 compliance suite indicates that it is OK to simply show an error in 
        // response to the request - which is what we will do for now. These tests really need to be rolled into 
        // ForgeRock AM as a FAPI compliant option.
        String[] requiredClaims = [ "scope", "state", "nonce" ]
        for (requiredClaim in requiredClaims) {
            if ( !requestJwtHasClaim(requiredClaim, requestJwtClaimSet) ) {
                return logMissingClaimAndGetBadRequestResponse("invalid_request", requiredClaim)
            }    
        }

        break
    default:
        logger.debug(SCRIPT_NAME + 'Method not supported')
        return new Response(Status.NOT_FOUND)
}

logger.info("Request is FAPI compliant - calling next.handle")
return next.handle(context, request)

private Response isRequestValidForRedirection(requestJwtClaims) {
    def redirectUri = requestJwtClaims.getClaim('redirect_uri')
    String[] requiredClaims = ['redirect_uri', 'client_id']
    for ( requiredClaim in requiredClaims ) {
        if (!requestJwtHasClaim(reqiredClaim, requestJwtClaims) ) {
            return logMissingClaimAndGetBadRequestResponse("invalid_request", requiredClaim)
        }
    }
    return null
}

private Boolean requestJwtHasClaim(String claimName, JwtClaimsSet requestJwtClaims) {
    return requestJwtClaims.getClaim(claimName)?true:false
}

private Response logMissingClaimAndGetBadRequestResponse(String errorType, String claimName) {
    String errorString = "error: " + errorType + "\nerrorDescription: Invalid Request JWT: must have '" + claimName + "' claim"
    logger.info(SCRIPT_NAME + errorString)
    return createBadRequestResponse(errorString)
}

private Response createBadRequestResponse(errorMessage) {
    def badRequestResponse = new Response(Status.BAD_REQUEST)
    badRequestResponse.setEntity(errorMessage)
    return badRequestResponse
}


private JwtClaimsSet getRequestJtwClaimSet() {
    String requestJwtString  = getQueryParamFromRequest('request')
    if (!requestJwtString) {
        logger.info(SCRIPT_NAME + 'BAD_REQUEST: /authorize request must have a request query parameter')
        return null
    }
    try {
        SignedJwt jwt = new JwtReconstruction().reconstructJwt(requestJwtString, SignedJwt.class)
        return jwt.getClaimsSet()
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
