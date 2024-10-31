import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import groovy.json.JsonSlurper


/*
 * Script to set entity to OB compliant response headers and body
 *
 * Ensure response header has interaction ID
 *
 * Ensure that response body is OB compliant on error
 *
 * If not HTTP error response, then allow through
 * If HTTP error response with OB error message (i.e. from RS), then allow through
 * If HTTP error response and OB error in shared state (i.e. from IG), then set response entity to OB error
 * If HTTP error response with no OB error in shared state, set response body to generic OB error
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ObResponseCheck] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

String HEADER_INTERACTION_ID = "x-fapi-interaction-id"
Map<String, String> getGenericError(Status status, String responseBody, boolean isV3Request) {

  String errorCode
  String message
  logger.debug(SCRIPT_NAME + "STATUS-*-: " + status)
  logger.debug(SCRIPT_NAME + "ERROR-*- body: " + responseBody)
  switch (status) {

    case Status.NOT_FOUND:
         errorCode = isV3Request ? "UK.OBIE.NotFound" : "U011"
         message = isV3Request ? "Resource not found" : "Resource cannot be found"
         break

    case Status.BAD_REQUEST:
      errorCode = isV3Request ? "UK.OBIE.Field.Invalid" : "U002"
      message = isV3Request ? "Bad request" : "Field is invalid"
      break

    case Status.UNAUTHORIZED:
      errorCode = "UK.OBIE.Unauthorized"
      message = "Unauthorized"
      break

    case Status.FORBIDDEN:
      errorCode = isV3Request ? "UK.OBIE.Reauthenticate" : "U028"
      message = isV3Request ? "Forbidden" : "Reauthentication is required by PSU"
      break

    case Status.INTERNAL_SERVER_ERROR:
      errorCode = isV3Request ? "UK.OBIE.UnexpectedError" : "U000"
      message = "Internal error"
      break

    default:
      errorCode = isV3Request ? "UK.OBIE.UnexpectedError" : "U000"
      message = "Internal error"
  }

  if (responseBody) {
    def slurper = new JsonSlurper()
    Map responseObj = slurper.parseText(responseBody)
    logger.debug(SCRIPT_NAME + "Response error from backend: " + responseObj)
    if(responseObj.Code){
      errorCode = responseObj.Errors[0].ErrorCode
      message = responseObj.Errors[0].Message
      path = responseObj.Errors[0].Path
      if (path) {
        return [
                ErrorCode: errorCode,
                Message: message,
                Path: path
        ]
      }
    }
    if (responseObj.error) {
      message += " [" + responseObj.error + "]"
    }
    if (responseObj.error_description) {
      message += " [" + responseObj.error_description + "]"
    }
    logger.debug(SCRIPT_NAME + "Response values errorCode= " + errorCode + ", message= " + message)
  }

  return [
          ErrorCode: errorCode,
          Message: message
  ]
}

// Placeholder right now - always assume that we don't have an OB compliant response already
//
// TODO: parse response body to see if already OB compliant response

static isObCompliantError(responseBody) {
  return false
}

boolean isV3Request(def request) {
  String apiVersionRegex = "(v\\d+)"
  def match = (request.uri.path =~ apiVersionRegex)
  def isV3Request = true
  if (match.find()) {
    def apiVersion = match.group(1)  // Capture only the major version, e.g., "v4"
    if (apiVersion == "v4") {
      return false
    }
  }
  return true;
}

def v3Request = isV3Request(request)

next.handle(context, request).thenOnResult({response ->

  // Check for OB compliant error response

  Status status = response.getStatus()
  String responseBody = response.getEntity().getString();

  // Build an OBErrorResponse1 response object
  if ((status.isClientError() || status.isServerError()) && !isObCompliantError(responseBody)) {

    def code = status.getCode()
    def reason = response.getCause()

    Map<String,String> newBody = [
            Code: code.toString()
    ]

    requestIds = request.headers.get("x-request-id")
    if (requestIds) {
      newBody.put("Id",requestIds.firstValue)
    }

    newBody.put("Message",  status.toString())

    def obErrorObject = getGenericError(status, responseBody, v3Request)
    errorList = [obErrorObject]
    newBody.put("Errors", errorList)
    logger.debug(SCRIPT_NAME + "Final Error Response: " + newBody)
    response.setEntity(newBody)
  }
})

