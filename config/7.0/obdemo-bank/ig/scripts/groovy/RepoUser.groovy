import groovy.json.JsonOutput

/*
curl \
--header "X-OpenIDM-Username: amadmin" \
--header "X-OpenIDM-Password: 2ssovx1TM3z2AGMGMJj01bic" \
--header "Accept-API-Version: resource=1.0" \
--request GET \
"https://iam.dev.forgerock.financial/openidm/managed/user/9cb7d12b-5de3-4a62-8c21-245e8953d3a0"
 */
// Fetch the API Client from IDM

Request userRequest = new Request();
userRequest.setMethod('GET');

// response object
response = new Response(Status.OK)
response.headers['Content-Type'] = "application/json"

def splitUri =  request.uri.path.split("/")

if (splitUri.length == 0) {
    message = "Can't parse api client ID from inbound request"
    logger.error(message)
    response.status = Status.BAD_REQUEST
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def userId = splitUri[splitUri.length - 1];

logger.debug("Looking up API Client {}",userId)

userRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjUser + "/" + userId)

http.send(userRequest).then(userResponse -> {
    userRequest.close()
    logger.debug("Back from IDM")

    def userResponseStatus = userResponse.getStatus();

    if (userResponseStatus != Status.OK) {
        message = "Failed to get user details"
        logger.error(message)
        response.status = userResponseStatus
        response.entity = "{ \"error\":\"" + message + "\"}"
        return response
    }

    def userResponseContent = userResponse.getEntity();
    def userResponseObject = userResponseContent.getJson();
    logger.debug("response JSON " + userResponseObject);

    def responseObj = [
            "id": userResponseObject._id,
            "userName": userResponseObject.userName,
            "givenName": userResponseObject.givenName,
            "surname": userResponseObject.sn,
            "mail": userResponseObject.mail,
            "accountStatus": userResponseObject.accountStatus
    ]

    def responseJson = JsonOutput.toJson(responseObj);
    logger.debug("Final JSON " + responseJson)

    response.entity = responseJson;
    return response

}).then(response -> { return response })
