import com.forgerock.sapi.gateway.common.jwt.JwtException
import com.forgerock.sapi.gateway.jwt.JwtUtils
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory
import org.forgerock.util.promise.*
import org.forgerock.http.protocol.*
import org.forgerock.json.JsonValue
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.jwt.Jwt
import java.net.URI
import groovy.json.JsonSlurper
import com.forgerock.securebanking.uk.gateway.jwks.*
import java.security.SignatureException
import com.nimbusds.jose.jwk.RSAKey;
import com.securebanking.gateway.dcr.ErrorResponseFactory
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement
import com.forgerock.sapi.gateway.common.jwt.ClaimsSetFacade
import static org.forgerock.util.promise.Promises.newResultPromise

/*
 * Script to verify the registration request, and prepare AM OIDC dynamic client reg
 * Input:  Registration JWT
 * Output: Verified OIDC registration JSON
 *
 * Relevant specifications:
 * https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-mapping
 * https://openid.net/specs/openid-connect-registration-1_0.html
 * https://datatracker.ietf.org/doc/html/rfc7591
 *
 * NOTE: This filter should be used AFTER the FAPIAdvancedDCRValidationFilter. That filter will check that the request
 * is fapi compliant:
 * - validateRedirectUris
 *   - request object must contain redirect_uris field
 *   - redirect_uris array must not be empty
 *   - redirect_uris contain valid URIs
 *   - redirect_uris must use https scheme
 * - validateResponseTypes
 *   - request object must contain field: response_types
 *   - response types are FAPI compliant, i.e. "code" or "code id_token"
 *   - if response type is "code", response_mode is "jwt"
 *   - if response type is "code id_token" then request must contain field 'scope' and scope must contain 'openid'
 * - validateSigningAlgorithmUsed
 *   - that the signing algorithm supported is PS256
 * - validateTokenEndpointAuthMethods
 *   - request object must contain field: token_endpoint_auth_method
 *   - that token_endpoint_auth_method is a valid value, either 'private_key_jwt' or 'tls_client_auth'
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if (fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[ProcessRegistration] (" + fapiInteractionId + ") - "
logger.debug(SCRIPT_NAME + "Running...")

def errorResponseFactory = new ErrorResponseFactory(SCRIPT_NAME)

def defaultResponseTypes = ["code id_token"]
def supportedResponseTypes = [defaultResponseTypes]

if (!attributes.registrationRequest) {
    logger.error(SCRIPT_NAME + "RegistrationRequestEntityValidatorFilter must be run prior to this script")
    return new Response(Status.INTERNAL_SERVER_ERROR)
}

RegistrationRequest registrationRequest = attributes.registrationRequest
if (! registrationRequest.signatureHasBeenValidated() ){
    logger.error(SCRIPT_NAME + "registrationResponse signature has not been validated. " +
            "RegistrationRequestJwtSignatureValidatorFilter must be run prior to this script")
    return new Response(Status.INTERNAL_SERVER_ERROR)
}

def method = request.method

switch (method.toUpperCase()) {
    case "POST":
    case "PUT":
        def SCOPE_ACCOUNTS = "accounts"
        def SCOPE_PAYMENTS = "payments"
        def ROLE_PAYMENT_INITIATION = "0.4.0.19495.1.2"
        def ROLE_ACCOUNT_INFORMATION = "0.4.0.19495.1.3"
        def ROLE_CARD_BASED_PAYMENT_INSTRUMENTS = "0.4.0.19495.1.4"

        // Check we have everything we need from the client certificate
        if (!attributes.clientCertificate) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No client certificate for registration")
        }
        if (!attributes.clientCertificate.roles) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("No roles in client certificate for registration")
        }

        Jwt regJwt = JwtUtils.getSignedJwtFromString(SCRIPT_NAME, request.entity.getString(), "registration JWT")
        if (!regJwt) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("registration request object is not a valid JWT")
        }

        if (registrationRequest.hasExpired()){
            logger.debug(SCRIPT_NAME + "Registration request JWT has expired")
            return errorResponseFactory.invalidClientMetadataErrorResponse("registration request jwt has expired")
        }

        // rejectInvalidResponseTypes - the FAPI filter does this for us. However, we currently can't support the
        // response_type "code" in conjunction with the response_mode value jwt that is allowed by the FAPI filter so
        // we will restrict this to "code id_token" here.
        ClaimsSetFacade regRequestClaimsSet = registrationRequest.getClaimsSet()
        Optional<List<String>> optionalResponseTypes = regRequestClaimsSet.getOptionalStringListClaim("response_types")
        if(optionalResponseTypes.isEmpty()){
            registrationRequest.setResponseTypes(defaultResponseTypes)
        } else {
            // https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1 states that:
            //   "The authorization server MAY reject or
            //   replace any of the client's requested metadata values submitted
            //   during the registration and substitute them with suitable values."
            if (!supportedResponseTypes.contains(optionalResponseTypes.get())){
               registrationRequest.setResponseTypes(defaultResponseTypes);
            }
        }

        // Check token_endpoint_auth_methods. OB Spec says this MUST be defined with 1..1 cardinality in the
        // registration request.
        Optional<String> optionalEndpointAuthMethod =
                regRequestClaimsSet.getOptionalStringListClaim("token_endpoint_auth_method")
        if ( optionalEndpointAuthMethod.isEmpty()){
            return errorResponseFactory.invalidClientMetadataErrorResponse("token_endpoint_auth_method must be specified")
        } else {
            if (!tokenEndpointAuthMethodsSupported.contains(optionalEndpointAuthMethod.get())){
                return errorResponseFactory.invalidClientMetadataErrorResponse(
                        "token_endpoint_auth_method claim must be one of: " + tokenEndpointAuthMethodsSupported)
            }
        }

        String tokenEndpointAuthMethod = optionalEndpointAuthMethod.get();
        // AM should reject this case??
        if (tokenEndpointAuthMethod.equals("tls_client_auth") && !registrationJwtClaimSet.getClaim("tls_client_auth_subject_dn")) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("tls_client_auth_subject_dn must be provided to use tls_client_auth")
        }

        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement()
        logger.debug(SCRIPT_NAME + "Got ssa [" + softwareStatement + "]")


        // This is nulled down because currently the SSA issued by the Open Banking Test Directory is not valid and is
        // rejected by AM. This is set to change when OBIE release a new version of the Directory in Feb 2023.
        // This should now be fixed, so let's see what happens eh???
        //registrationJwtClaimSet.setClaim("software_statement", null);

        // This is OB specific
        // Validate the issuer claim for the registration matches the SSA software_id
        // NOTE: At this stage we do not know if the SSA is valid, it is assumed the SSAVerifier filter will run after
        //       this filter and raise an error if the SSA is invalid.
        String registrationIssuer = registrationRequest.getIssuer()
        String ssaSoftwareId = softwareStatement.getSoftwareId()
        logger.debug("{}registrationIssuer is {}, ssaSoftwareId is {}", SCRIPT_NAME, registrationIssuer, ssaSoftwareId)
        if (registrationIssuer == null || ssaSoftwareId == null || registrationIssuer != ssaSoftwareId) {
            return errorResponseFactory.invalidClientMetadataErrorResponse("invalid issuer claim")
        }

        def apiClientOrgId = softwareStatement.getOrgId()
        def apiClientOrgName = apiClientOrgId
        logger.debug(SCRIPT_NAME + "Inbound details from SSA: apiClientOrgName: {} apiClientOrgCertId: {}",
                apiClientOrgName,
                apiClientOrgId
        )

          // This structure is no longer used by subsequent filters
//        // This structure ends up being put added to the attributes context and is used by the CreateApiClient.groovy
//        // script to create - was used by SSAVerifier too. Have removed SSAVerifier from the route as all the
//        // verification is now done in the RegistrationRequestEntityValidatorFilter
//        def registrationJWTs = [
//                "ssaStr"             : softwareStatement.getB64EncodedJwtString(),
//                "ssaJwt"             : softwareStatement.getSignedJwt(),
//                "registrationJwt"    : regJwt,
//                "registrationJwksUri": null,
//                "registrationJwks"   : null
//        ]
//
//
//        if (softwareStatement.hasJwksUri()) {
//            registrationJWTs["registrationJwksUri"] = softwareStatement.getJwksUri()
//        } else {
//            registrationJWTs["registrationJwks"] = softwareStatement.getJwks();
//        }

        // Update OIDC registration request
        // TODO: Work out why we set jwks_uri and jwks claims in the registration request! Do we need to do this?
//        if (trustedDirectory.softwareStatementHoldsJwksUri()) {
//            def apiClientOrgJwksUri = ssaClaims.getClaim(trustedDirectory.getSoftwareStatementJwksUriClaimName());
//            if (routeArgObJwksHosts) {
//                // If the JWKS URI host is in our list of private JWKS hosts, then proxy back through IG
//                def jwksUri = null;
//                try {
//                    jwksUri = new URI(apiClientOrgJwksUri)
//                }
//                catch (e) {
//                    return errorResponseFactory.invalidSoftwareStatementErrorResponse("software_jwks_endpoint does not contain a valid URI")
//                }
//                // If the JWKS URI host is in our list of private JWKS hosts, then proxy back through IG
//                if (routeArgObJwksHosts && routeArgObJwksHosts.contains(jwksUri.getHost())) {
//                    def newUri = routeArgProxyBaseUrl + "/" + jwksUri.getHost() + jwksUri.getPath();
//                    logger.debug(SCRIPT_NAME + "Updating private JWKS URI from {} to {}", apiClientOrgJwksUri, newUri);
//                    apiClientOrgJwksUri = newUri
//
//                }
//            }
//            logger.debug(SCRIPT_NAME + "Using jwks uri: {}", apiClientOrgJwksUri)
//            registrationJwtClaimSet.setClaim("jwks_uri", apiClientOrgJwksUri)
//            registrationJWTs["registrationJwksUri"] = apiClientOrgJwksUri
//        } else {
//            def apiClientJwks = ssaClaims.getClaim(trustedDirectory.getSoftwareStatementJwksClaimName());
//            logger.debug(SCRIPT_NAME + "Using jwks from software_statement")
//            registrationJwtClaimSet.setClaim("jwks", apiClientJwks)
//            registrationJWTs["registrationJwks"] = apiClientJwks
//        }

        // The Jwks will be added by filters run on each route... we won't need  to store them here.
        // Store SSA and registration JWT for signature check
        attributes.registrationJWTs = registrationJWTs

        // ToDo: Why are we setting client name here??
        // registrationJwtClaimSet.setClaim("client_name", apiClientOrgName)

        // ToDo: I don't think we should force this. We do checks in each route to ensure that the TLS certificate is
        // validatable by the jwks_uri. Tying the access tokens to the cert used to obtain the access token may cause
        // issues if a TPP renews a cert. The access token would be then unable to be used with the new cert, and the
        // TPP would have to go through a consent flow again to get an access token associated with the new cert.
        // registrationJwtClaimSet.setClaim("tls_client_certificate_bound_access_tokens", true)

        // ToDo: Why is this here?
        def subject_type = registrationJwtClaimSet.getClaim("subject_type", String.class);
        if (!subject_type) {
            registrationJwtClaimSet.setClaim("subject_type", "pairwise");
        }

        Response errorResponse = performOpenBankingScopeChecks(errorResponseFactory, registrationRequest)
        if (errorResponse != null) {
            return errorResponse
        }

        // TODO: Subject DN for cert bound access tokens

        // AM doesn't understand JWS encoded registration requests, so we need to convert the jwt JSON and pass it on
        // However, this might not be the best place to do that?
        def regJson = registrationJwtClaimSet.build();
        logger.debug(SCRIPT_NAME + "final json [" + regJson + "]")
        request.setEntity(regJson)

        // Put is editing an existing registration, so needs the client_id param in the uri
        if (request.method == "PUT") {
            rewriteUriToAccessExistingAmRegistration()
        }

        // Verify that the tls transport cert is registered for the TPP's software statement
        if ( softwareStatement.hasJwksUri() ) {
            URL softwareStatementJwksUri = softwareStatement.getJwksUri();
            logger.debug(SCRIPT_NAME + "Checking cert against remote jwks: " + softwareStatementJwksUri)
            return jwkSetService.getJwkSet(softwareStatementJwksUri)
                    .thenCatchAsync(e -> {
                        String errorDescription = "Unable to get jwks from url: " + softwareStatementJwksUri
                        logger.warn(SCRIPT_NAME + "Failed to get jwks due to exception: " + errorDescription, e)
                        return newResultPromise(errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription))
                    })
                    .thenAsync(jwkSet -> {
                        if (!tlsClientCertExistsInJwkSet(jwkSet)) {
                            String errorDescription = "tls transport cert does not match any certs " +
                                    "registered in jwks for software statement"
                            logger.debug("{}{}", SCRIPT_NAME, errorDescription)
                            return newResultPromise(errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription))
                        }
                        if (!validateRegistrationJwtSignature(regJwt, jwkSet)) {
                            String errorDescription = "registration JWT signature invalid"
                            logger.debug("{}{}", SCRIPT_NAME, errorDescription)
                            return newResultPromise(errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription))
                        }
                        return next.handle(context, request)
                                .thenOnResult(response -> addSoftwareStatementToResponse(response, ssa))
                    })
        } else {
            // Verify against the software_jwks which is a JWKSet embedded within the software_statement
            // NOTE: this is only suitable for developer testing purposes
            if (!allowIgIssuedTestCerts) {
                String errorDescription = "software_statement must contain software_jwks_endpoint"
                return errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription)
            }
            JWKSet apiClientJwkSet = softwareStatement.getJwksSet()
            logger.debug(SCRIPT_NAME + "Checking cert against ssa software_jwks: " + apiClientJwks)
            if (!tlsClientCertExistsInJwkSet(apiClientJwkSet)) {
                String errorDescription = "tls transport cert does not match any certs registered in jwks for software " +
                        "statement"
                logger.debug("{}{}", SCRIPT_NAME, errorDescription)
                return newResultPromise(errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription))
            }
            if (!validateRegistrationJwtSignature(regJwt, apiClientJwkSet)) {
                String errorDescription = "registration JWT signature invalid"
                logger.debug("{}{}", SCRIPT_NAME, errorDescription)
                return newResultPromise(errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription))
            }
            return next.handle(context, request)
                    .thenOnResult(response -> addSoftwareStatementToResponse(response, ssa))
        }

    case "DELETE":
        rewriteUriToAccessExistingAmRegistration()
        return next.handle(context, request)
    case "GET":
        rewriteUriToAccessExistingAmRegistration()
        return next.handle(context, request)
                .thenOnResult(response -> {
                    var apiClient = attributes.apiClient
                    if (apiClient && apiClient.ssa) {
                        addSoftwareStatementToResponse(response, apiClient.ssa)
                    }
                })
    default:
        logger.debug(SCRIPT_NAME + "Method not supported")
        return next.handle(context, request)

}

/**
 * This method enforces the rule set by OBIE
 * <a href="https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#data-mapping">here</a>
 * that states:
 * "scope: Specified in the scope claimed. This must be a subset of the scopes in the SSA"
 * also in the
 * <a href="https://openbankinguk.github.io/dcr-docs-pub/v3.3/dynamic-client-registration.html#obclientregistrationrequest1">
 * data dictionary for OBClientRegistrationRequest1 </a>
 * it is stated that:
 * "scope 	1..1 	scope 	Scopes the client is asking for (if not specified, default scopes are assigned by the AS).
 * This consists of a list scopes separated by spaces. 	String(256)"
 *
 * In the Open Banking issued SSA we can find no scopes defined, however, we do have 'software_roles' which is an array
 * of strings containing AISP, PISP, or a subset thereof, or ASPSP. We must check that the scopes requested are allowed
 * according to the roles defined in the software statement.
 *
 * @param registrationRequestClaims The claims from the registration request jwt
 * @param ssaClaims the claims from the ssa
 * @return false if the OBIE specification rules are met, true if they are not
 */
private Response performOpenBankingScopeChecks(ErrorResponseFactory errorResponseFactory) {
    logger.debug("{}performing OpenBanking Scope tests", SCRIPT_NAME)

    ClaimsSetFacade registrationRequestClaims = registrationRequest.getClaimsSet()

    String requestedScopes;
    try {
        requestedScopes = registrationRequestClaims.getStringClaim("scope")
    } catch (JwtException jwtException) {

            String errorDescription = "The request jwt does not contain the required scopes claim"
            logger.info(SCRIPT_NAME + errorDescription)
            return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }
    logger.debug("{}requestedScopes are {}", SCRIPT_NAME, requestedScopes)

    ClaimsSetFacade softwareStatementClaims = registrationRequest.getSoftwareStatement().getClaimsSet()

    List<String> ssaRoles
    try {
        ssaRoles = softwareStatementClaims.getRequiredStringListClaim("software_roles")
    } catch (JwtException jwtException) {
        String errorDescription = "The software_statement jwt does not contain a 'software_roles' claim"
        logger.debug(SCRIPT_NAME + errorDescription)
        return errorResponseFactory.invalidSoftwareStatementErrorResponse(errorDescription)
    }
    logger.debug("{}ssaRoles are {}", SCRIPT_NAME, ssaRoles)

    if (requestedScopes.contains("accounts") && !ssaRoles.contains("AISP")) {
        String errorDescription = "registration request contains scopes not allowed " +
                "for the presented software statement"
        logger.debug("{}{}{}", SCRIPT_NAME, errorDescription, ": accounts")
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }

    if (requestedScopes.contains("payments") && !ssaRoles.contains("PISP")) {
        String errorDescription = "registration request contains scopes not allowed " +
                "for the presented software statement"
        logger.debug("{}{}{}", SCRIPT_NAME, errorDescription, ": payments")
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }

    if (requestedScopes.contains("fundsconformations") && !ssaRoles.contains("CBPII")) {
        String errorDescription = "registration request contains scopes not allowed " +
                "for the presented software statement"
        logger.debug("{}{}{}", SCRIPT_NAME, errorDescription, ": fundsconformations")
        return errorResponseFactory.invalidClientMetadataErrorResponse(errorDescription)
    }

    logger.debug("{} passed Open Banking scope tests", SCRIPT_NAME)
    return null;
}

/**
 * For operations on an existing registration, AM expects a uri of the form:
 *   am/oauth2/realms/root/realms/alpha/register?client_id=8ed73b58-bd18-41c4-93f3-7a1bbf57a7eb
 *
 * This method takes the OB uri form: am/oauth2/realms/root/realms/alpha/8ed73b58-bd18-41c4-93f3-7a1bbf57a7eb and
 * rewrites it to the AM form.
 */
private void rewriteUriToAccessExistingAmRegistration() {
    def path = request.uri.path
    def lastSlashIndex = path.lastIndexOf("/")
    def apiClientId = path.substring(lastSlashIndex + 1)
    request.uri.setRawPath(path.substring(0, lastSlashIndex))
    request.uri.setRawQuery("client_id=" + apiClientId)
}

private void addSoftwareStatementToResponse(response, ssa) {
    if (response.status.isSuccessful()) {
        var registrationResponse = response.getEntity().getJson()
        if (!registrationResponse["software_statement"]) {
            registrationResponse["software_statement"] = ssa
        }
        response.entity.setJson(registrationResponse)
    }
}

private boolean tlsClientCertExistsInJwkSet(jwkSet) {
    def tlsClientCert = attributes.clientCertificate.certificate
    // RSAKey.parse produces a JWK, we can then extract the cert from the x5c field
    def tlsClientCertX5c = RSAKey.parse(tlsClientCert).getX509CertChain().get(0).toString()
    for (JWK jwk : jwkSet.getJWKsAsList()) {
        final List<String> x509Chain = jwk.getX509Chain();
        final String jwkX5c = x509Chain.get(0);
        if ("tls".equals(jwk.getUse()) && tlsClientCertX5c.equals(jwkX5c)) {
            logger.debug(SCRIPT_NAME + "Found matching tls cert for provided pem, with kid: " + jwk.getKeyId()
                    + " x5t#S256: " + jwk.getX509ThumbprintS256())
            return true
        }
    }
    logger.debug(SCRIPT_NAME + "tls transport cert does not match any certs registered in jwks for software statement")
    return false
}

private boolean validateRegistrationJwtSignature(jwt, jwkSet) {
    try {
        jwtSignatureValidator.validateSignature(jwt, jwkSet)
        return true
    } catch (SignatureException se) {
        logger.warn(SCRIPT_NAME + "jwt signature validation failed", se)
        return false
    }
}

