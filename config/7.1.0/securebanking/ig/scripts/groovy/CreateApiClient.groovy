import org.forgerock.http.protocol.*
import groovy.json.JsonOutput
import org.forgerock.json.jose.*
import static org.forgerock.util.promise.Promises.newResultPromise

/*
 * Filter to manage AM apiClient and apiClientOrg objects in IDM
 *
 * All functionality is triggered upon a successful response from AM.
 *
 * New apiClient and apiClientOrg objects are created in IDM when a new DCR has been completed. Note, the apiClientOrg
 * may already exist, in which case only the apiClient is created. In both cases, the apiClient is linked to the apiClientOrg
 *
 * Get and Delete operations are also supported for existing IDM apiClient objects
 */

/**
 * 412 Precondition Failed: The resource’s current version does not match the version provided.
 * Returned by IDM when this filter attempts to create an apiClientOrg that already exists
 * https://backstage.forgerock.com/docs/idm/7.2/crest/crest-status-codes.html
 */
HTTP_PRECONDITION_FAILED = 412

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[CreateApiClient] (" + fapiInteractionId + ") - ";
logger.debug(SCRIPT_NAME + "Running...")

def errorResponse(httpCode, message) {
  logger.error(SCRIPT_NAME + "Returning error " + httpCode + ": " + message);
  def response = new Response(httpCode);
  response.headers['Content-Type'] = "application/json";
  response.entity = "{ \"error\":\"" + message + "\"}";
  return response;
}

def method = request.method

switch(method.toUpperCase()) {

  case "POST":
    return next.handle(context, request).thenAsync(amResponse -> {
      // Do not create ApiClient if AM did not successfully process the registration
      if (!amResponse.status.isSuccessful()) {
        return newResultPromise(amResponse)
      }
      if (!attributes.registrationJWTs) {
        logger.error(SCRIPT_NAME + "Required attribute not found: attributes.registrationJWTs")
        return newResultPromise(errorResponse(Status.INTERNAL_SERVER_ERROR, "Missing request data"))
      }
      if (!attributes.registrationJWTs.ssaJwt || !attributes.registrationJWTs.ssaStr) {
        logger.error(SCRIPT_NAME + "One or more required attributes are null: attributes.registrationJWTs.ssaJwt={}," +
                " attributes.registrationJWTs.ssaStr={}", attributes.registrationJWTs.ssaJwt, attributes.registrationJWTs.ssaStr)
        return newResultPromise(errorResponse(Status.INTERNAL_SERVER_ERROR, "Missing request data"))
      }
      if (!attributes.registrationJWTs.registrationJwksUri && !attributes.registrationJWTs.registrationJwks
              || attributes.registrationJWTs.registrationJwksUri && attributes.registrationJWTs.registrationJwks ) {
        logger.error(SCRIPT_NAME + "Exactly one of following attributes must be set: attributes.registrationJWTs.registrationJwksUri={}," +
                " attributes.registrationJWTs.registrationJwks={}",
                attributes.registrationJWTs.registrationJwksUri, attributes.registrationJWTs.registrationJwks)
        return newResultPromise(errorResponse(Status.INTERNAL_SERVER_ERROR, "Missing request data"))
      }

      def ssaJwt = attributes.registrationJWTs.ssaJwt
      def oauth2ClientId = amResponse.entity.getJson().client_id
      if (!oauth2ClientId) {
        logger.error(SCRIPT_NAME + "Required client_id field not found in AM registration response")
        return newResultPromise(errorResponse(Status.INTERNAL_SERVER_ERROR, "Failed to get client_id"))
      }
      def ssaClaims = ssaJwt.getClaimsSet()
      def organisationName = ssaClaims.getClaim("org_name")
      def organisationIdentifier = ssaClaims.getClaim("org_id")
      def apiClientOrgIdmObject = buildApiClientOrganisationIdmObject(organisationIdentifier, organisationName)
      def apiClientIdmObject = buildApiClientIdmObject(oauth2ClientId, ssaClaims)

      return createApiClientOrganisation(apiClientOrgIdmObject).thenAsync(createApiClientOrgResponse -> {
        if (!createApiClientOrgResponse.status.isSuccessful()) {
          return newResultPromise(createApiClientOrgResponse)
        }
        return createApiClient(apiClientIdmObject).then(createApiClientResponse -> {
          if (!createApiClientResponse.status.isSuccessful()) {
            return createApiClientResponse
          } else {
            // Return the original AM success response if we created the IDM objects
            return amResponse
          }
        })
      })
    })
  case "DELETE":
    return next.handle(context, request).thenAsync(response -> {
      // Delete IDM object only if AM delete was successful
      if (response.status.isSuccessful()) {
        // ProcessRegistration filter will have added the client_id param
        def apiClientId = request.getQueryParams().getFirst("client_id")
        Request deleteApiClientReq = new Request()
        deleteApiClientReq.setMethod('DELETE')
        deleteApiClientReq.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientId)
        logger.info("Deleting IDM object: " + routeArgObjApiClient + " for client_id: " + apiClientId)
        return http.send(deleteApiClientReq).thenAsync(idmResponse -> {
          if (idmResponse.status.isSuccessful()) {
            logger.debug("IDM object successfully deleted for client_id: " + apiClientId)
            return newResultPromise(new Response(Status.NO_CONTENT))
          }
          return newResultPromise(errorResponse(Status.BAD_REQUEST, "Failed to delete registration"))
        })
      }
      // AM returned an error, pass this on
      return newResultPromise(response)
    })
  case "GET":
    // Fetch the apiClient from IDM and add it as an attribute for use by other filters
    return next.handle(context, request).thenAsync(amResponse -> {
      if (amResponse.status.isSuccessful()) {
        def apiClientId = request.getQueryParams().getFirst("client_id")
        Request getApiClient = new Request()
        getApiClient.setMethod('GET')
        getApiClient.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "/" + apiClientId)
        logger.info("Retrieving IDM object: " + routeArgObjApiClient + " for client_id: " + apiClientId)
        return http.send(getApiClient).thenAsync(idmResponse -> {
          if (idmResponse.status.isSuccessful()) {
            var apiClient = idmResponse.getEntity().getJson()
            attributes.apiClient = apiClient
          }
          // Pass the original AM response on, the IDM response is only used to enrich the AM response (on a best effort basis)
          return newResultPromise(amResponse)
        })
      }
      // AM returned an error, pass this on
      return newResultPromise(amResponse)
    })
  default:
    logger.debug(SCRIPT_NAME + "Method not supported")
    next.handle(context, request)
}

def buildApiClientIdmObject(oauth2ClientId, ssaClaims) {
  def clientJwksUri = attributes.registrationJWTs.registrationJwksUri
  def clientJwks = attributes.registrationJWTs.registrationJwks
  def apiClientConfig = [
          "_id"           : oauth2ClientId,
          "id"            : ssaClaims.getClaim("software_client_id"),
          "name"          : ssaClaims.getClaim("software_client_name"),
          "description"   : ssaClaims.getClaim("software_client_description"),
          "ssa"           : attributes.registrationJWTs.ssaStr,
          "logoUri"       : ssaClaims.getClaim("software_logo_uri"),
          "oauth2ClientId": oauth2ClientId,
          "apiClientOrg"  : ["_ref": "managed/" + routeArgObjApiClientOrg + "/" + ssaClaims.getClaim("org_id")]
  ]

  if (clientJwksUri) {
    apiClientConfig.jwksUri = clientJwksUri
  }
  if (clientJwks) {
    apiClientConfig.jwks = JsonOutput.toJson(clientJwks)
  }
  return apiClientConfig
}

def buildApiClientOrganisationIdmObject(organisationIdentifier, organisationName) {
  return [
          "_id" : organisationIdentifier,
          "id"  : organisationIdentifier,
          "name": organisationName,
  ]
}

def createApiClientOrganisation(apiClientOrgIdmObject) {
  Request apiClientOrgRequest = new Request()
  apiClientOrgRequest.setMethod('PUT')
  apiClientOrgRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClientOrg + "/" + apiClientOrgIdmObject["_id"])
  apiClientOrgRequest.addHeaders(new GenericHeader("If-None-Match", "*")) // Prevent updating an existing apiClientOrg
  apiClientOrgRequest.setEntity(apiClientOrgIdmObject)
  return http.send(apiClientOrgRequest).then(apiClientOrgResponse -> {
    if (!apiClientOrgResponse.status.isSuccessful() && apiClientOrgResponse.status.code != HTTP_PRECONDITION_FAILED) {
      logger.error(SCRIPT_NAME + "unexpected IDM response when attempting to create {}, status: {}, entity: {}", routeArgObjApiClientOrgapiClientOrgResponse, apiClientOrgResponse.status, apiClientOrgResponse.entity)
      return new Response(Status.INTERNAL_SERVER_ERROR)
    } else {
      logger.debug(SCRIPT_NAME + "organisation created OR already exists")
      return new Response(Status.OK)
    }
  })
}

def createApiClient(apiClientIdmObject) {
  Request apiClientRequest = new Request()
  apiClientRequest.setMethod('POST')
  apiClientRequest.setUri(routeArgIdmBaseUri + "/openidm/managed/" + routeArgObjApiClient + "?_action=create")
  apiClientRequest.setEntity(apiClientIdmObject)

  logger.debug(SCRIPT_NAME + "Sending apiClient create request to IDM endpoint")
  return http.send(apiClientRequest).then(apiClientResponse -> {
    if (apiClientResponse.status != Status.CREATED) {
      logger.error(SCRIPT_NAME + "unexpected IDM response when attempting to create {}, status: {}, entity: {}", routeArgObjApiClient, apiClientResponse.status, apiClientResponse.entity)
      return new Response(Status.INTERNAL_SERVER_ERROR)
    } else {
      logger.debug(SCRIPT_NAME + "successfully created apiClient")
      return new Response(Status.OK)
    }
  })
}
