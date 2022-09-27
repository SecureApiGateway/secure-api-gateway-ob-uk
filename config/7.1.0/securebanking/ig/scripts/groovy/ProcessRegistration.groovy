import org.forgerock.http.protocol.*
import org.forgerock.json.jose.*
import org.forgerock.json.jose.jwk.*
import org.forgerock.json.jose.common.JwtReconstruction
import org.forgerock.json.jose.jws.SignedJwt
import java.net.URI
import groovy.json.JsonSlurper
import com.forgerock.securebanking.uk.gateway.jwks.*
import static org.forgerock.util.promise.Promises.newResultPromise

/*
 * Script to verify the registration request, and prepare AM OIDC dynamic client reg
 * Input:  Registration JWT
 * Output: Verified OIDC registration JSON
 */

SCRIPT_NAME = "[ProcessRegistration] - "
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

        def error = false

        def SCOPE_ACCOUNTS = "accounts"
        def SCOPE_PAYMENTS = "payments"


        def ROLE_PAYMENT_INITIATION             = "0.4.0.19495.1.2"
        def ROLE_ACCOUNT_INFORMATION            = "0.4.0.19495.1.3"
        def ROLE_CARD_BASED_PAYMENT_INSTRUMENTS = "0.4.0.19495.1.4"

        // Check we have everything we need from the client certificate

        if (!attributes.clientCertificate) {
            return(errorResponse(Status.BAD_REQUEST,"No client certificate for registration"));
        }

        if (!attributes.clientCertificate.roles) {
            return(errorResponse(Status.BAD_REQUEST,"No roles in client certificate for registration"));
        }

        // Parse incoming registration JWT

        logger.debug(SCRIPT_NAME + "Parsing registration request");

        def regJwt = new JwtReconstruction().reconstructJwt(request.entity.getString(),SignedJwt.class)

        // TODO: Check signature

        // Pull the SSA from the reg data

        def oidcRegistration = regJwt.getClaimsSet();

        def ssa = oidcRegistration.getClaim("software_statement", String.class);

        if (!ssa) {
            return(errorResponse(Status.BAD_REQUEST,"No SSA"));
        }

        oidcRegistration.setClaim("software_statement",null);

        logger.debug(SCRIPT_NAME + "Got ssa [" + ssa + "]")

        def ssaJwt = new JwtReconstruction().reconstructJwt(ssa,SignedJwt.class)

        def ssaClaims = ssaJwt.getClaimsSet();

        def apiClientOrgName = ssaClaims.getClaim("software_client_name", String.class);
        def apiClientOrgCertId = ssaClaims.getClaim("org_id", String.class);
        def apiClientOrgJwksUri = ssaClaims.getClaim("software_jwks_endpoint");
        def apiClientOrgJwks = ssaClaims.getClaim("software_jwks");


        logger.debug(SCRIPT_NAME + "Inbound details from SSA: apiClientOrgName: {} apiClientOrgCertId: {} apiClientOrgJwksUri: {} apiClientOrgJwks: {}",
                apiClientOrgName,
                apiClientOrgCertId,
                apiClientOrgJwksUri,
                apiClientOrgJwks
        )

        // Update OIDC registration request

        if (apiClientOrgJwksUri) {
            logger.debug(SCRIPT_NAME + "Using jwks uri")
            if (routeArgObJwksHosts) {

                // If the JWKS URI host is in our list of private JWKS hosts, then proxy back through IG

                def slurper = new JsonSlurper()
                def proxiedHosts = slurper.parseText(routeArgObJwksHosts);

                if (!proxiedHosts) {
                    return(errorResponse(Status.INTERNAL_SERVER_ERROR,"Could not parse proxied jwks hosts"));
                }
                def jwksUri = null;
                try {
                    jwksUri = new URI(apiClientOrgJwksUri);
                }
                catch (e) {
                    return(errorResponse(Status.BAD_REQUEST,"Invalid JWKS URI: " + apiClientOrgJwksUri));
                }

                if (proxiedHosts.asList().contains(jwksUri.getHost())) {
                    def newUri = routeArgProxyBaseUrl + "/" + jwksUri.getHost() + jwksUri.getPath();
                    logger.debug(SCRIPT_NAME + "Updating private JWKS URI from {} to {}",apiClientOrgJwksUri,newUri);
                    apiClientOrgJwksUri = newUri;

                }
            }
            oidcRegistration.setClaim("jwks_uri", apiClientOrgJwksUri)
        }
        else if (apiClientOrgJwks) {
            logger.debug(SCRIPT_NAME + "Using jwks")
            oidcRegistration.setClaim("jwks",  apiClientOrgJwks )
        }
        else {
            return(errorResponse(Status.BAD_REQUEST,"No JWKS or JWKS URI in SSA"));
        }

        // Store SSA and registration JWT for signature check

        attributes.registrationJWTs = [
                "ssaJwt" : ssaJwt,
                "registrationJwt": regJwt,
                "registrationJwksUri": apiClientOrgJwksUri,
                "registrationJwks": apiClientOrgJwks
        ]

        oidcRegistration.setClaim("client_name",apiClientOrgName)
        oidcRegistration.setClaim("tls_client_certificate_bound_access_tokens", true)

        // Sanity check on scopes

        def scopes = oidcRegistration.getClaim("scope")
        def roles = attributes.clientCertificate.roles

        if (scopes.contains(SCOPE_ACCOUNTS) && !(roles.contains(ROLE_ACCOUNT_INFORMATION))) {
            return(errorResponse(Status.BAD_REQUEST,"Requested scope " + SCOPE_ACCOUNTS + " requires certificate role " + ROLE_ACCOUNT_INFORMATION));
        }

        if (scopes.contains(SCOPE_PAYMENTS) && !(roles.contains(ROLE_PAYMENT_INITIATION))) {
            return(errorResponse(Status.BAD_REQUEST,"Requested scope " + SCOPE_PAYMENTS + " requires certificate role " + ROLE_PAYMENT_INITIATION));
        }

        // Cross check ID with cert
        //
        // e.g. PSDGB-FFA-5f563e89742b2800145c7da1 or PSDGB-OB-Unknown0015800001041REAAY (issue by OB)

        def  organizationalIdentifier = attributes.clientCertificate.subjectDNComponents.OI

        if (!organizationalIdentifier) {
            return(errorResponse(Status.BAD_REQUEST,"No organizational identifier in cert"));
        }

        def oiComponents = organizationalIdentifier.split("-")

        if (oiComponents.length > 3) {
            return(errorResponse(Status.BAD_REQUEST,"Wrong number of dashes in OI " + organizationalIdentifier +" - expected 2"));
        }

        // TODO: Subject DN for cert bound access tokens

        // Convert to JSON and pass it on
        def regJson = oidcRegistration.build();
        logger.debug(SCRIPT_NAME + "final json [" + regJson + "]")
        request.setEntity(regJson)

        // Verify that the tls transport cert is registered for the TPP's software statement
        return jwkSetService.getJwkSet(new URL(apiClientOrgJwksUri)).thenAsync(jwkSet -> {
            // OB JWKS will store the cert in the x5c field as a pem without line breaks and begin/end lines
            def clientCertPem = attributes.clientCertificate.pem
            clientCertPem = clientCertPem.replaceAll("-----BEGIN CERTIFICATE-----", "")
            clientCertPem = clientCertPem.replaceAll("-----END CERTIFICATE-----", "")
            clientCertPem = clientCertPem.replaceAll("\n", "")
            logger.info(SCRIPT_NAME + "Cleaned up cert: " + clientCertPem)

            def found = false
            for (JWK jwk : jwkSet.getJWKsAsList()) {
                final List<String> x509Chain = jwk.getX509Chain();
                final String jwkCert = x509Chain.get(0);
                if ("tls".equals(jwk.getUse()) && clientCertPem.equals(jwkCert)) {
                    logger.debug(SCRIPT_NAME + "Found matching tls cert for provided pem, with kid: " + jwk.getKeyId())
                    found = true
                    break
                }
            }
            if (found) {
                return next.handle(context, request)
            } else {
                return newResultPromise(errorResponse(Status.BAD_REQUEST,"tls transport cert does not match any certs registered in software_jwks_endpoint"))
            }
        })
    case "DELETE":
       break

    default:
        logger.debug(SCRIPT_NAME + "Method not supported")

}

next.handle(context, request)







