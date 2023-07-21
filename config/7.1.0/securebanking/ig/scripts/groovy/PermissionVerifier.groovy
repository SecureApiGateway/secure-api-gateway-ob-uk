import org.forgerock.http.protocol.*
import com.forgerock.sapi.gateway.rest.HttpHeaderNames

String fapiInteractionId = request.getHeaders().getFirst(HttpHeaderNames.X_FAPI_INTERACTION_ID)
if (fapiInteractionId == null) {
    fapiInteractionId = 'No ' + HttpHeaderNames.X_FAPI_INTERACTION_ID + ' header'
}
SCRIPT_NAME = '[PermissionVerifier] (' + fapiInteractionId + ') - '
logger.debug(SCRIPT_NAME + 'Running...')

// supported method: POST
if (request.getMethod() == "POST") {
    def permissionTypeFromRequest = request.entity.getJson().Data.Permissions
    logger.debug(SCRIPT_NAME + 'permissionTypeFromRequest: ' + permissionTypeFromRequest)

    // Only allow the request to continue if we have a single PermissionType and its value is 'ReadCustomerInfoPSU'
    if (permissionTypeFromRequest.size() == 1 && permissionTypeFromRequest.contains('ReadCustomerInfoPSU')) {
        return next.handle(context, request)
        //call RS
    }

    Response response = new Response(Status.BAD_REQUEST)
    String message = 'Invalid Permission type, only ReadCustomerInfoPSU permission is supported.'
    logger.error(SCRIPT_NAME + message)
    response.headers['Content-Type'] = 'application/json'
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

next.handle(context, request)

