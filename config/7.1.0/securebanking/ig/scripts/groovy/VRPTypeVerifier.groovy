import org.forgerock.http.protocol.*
import com.forgerock.sapi.gateway.rest.HttpHeaderNames

String fapiInteractionId = request.getHeaders().getFirst(HttpHeaderNames.X_FAPI_INTERACTION_ID)
if (fapiInteractionId == null) {
    fapiInteractionId = 'No ' + HttpHeaderNames.X_FAPI_INTERACTION_ID + ' header'
}
SCRIPT_NAME = '[VRPTypeVerifier] (' + fapiInteractionId + ') - '
logger.debug(SCRIPT_NAME + 'Running...')

def vrpTypeFromRequest = request.entity.getJson().Data.ControlParameters.VRPType
logger.debug(SCRIPT_NAME + 'ControlParameters' + request.entity.getJson().Data.ControlParameters)
logger.debug(SCRIPT_NAME + 'vrpTypeFromRequest: ' + vrpTypeFromRequest)

def vrpAllowed = false

for (String vrpType : vrpTypeFromRequest) {
    logger.debug(SCRIPT_NAME + 'vrpType: ' + vrpType)
    if (vrpType == 'UK.OBIE.VRPType.Sweeping') {
        vrpAllowed = true;
        break;
    }
}

logger.debug(SCRIPT_NAME + 'vrpAllowed: ' + vrpAllowed)

if (!vrpAllowed) {
    Response response = new Response(Status.BAD_REQUEST)
    String message = 'Invalid VRP type, only Sweeping payments are supported.'
    logger.error(SCRIPT_NAME + message)
    response.headers['Content-Type'] = 'application/json'
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

next.handle(context, request)