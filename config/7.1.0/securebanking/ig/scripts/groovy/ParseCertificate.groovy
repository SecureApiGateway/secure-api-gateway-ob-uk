import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.net.URLDecoder
import javax.naming.ldap.LdapName
import javax.naming.ldap.Rdn
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DEROctetString
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1OctetString
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.interfaces.RSAPublicKey;


/*
 * Utility funcs for parsing certificate contents
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[ParseCertificate] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

class CertificateParserHelper {
    private static final EXTENDED_KEY_USAGE_OID_STRINGS = [
            "2.5.29.37.0",
            "1.3.6.1.5.5.7.3.0",
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2",
            "1.3.6.1.5.5.7.3.3",
            "1.3.6.1.5.5.7.3.4",
            "1.3.6.1.5.5.7.3.5",
            "1.3.6.1.5.5.7.3.6",
            "1.3.6.1.5.5.7.3.7",
            "1.3.6.1.5.5.7.3.8",
            "1.3.6.1.4.1.311.20.2.2",
            "1.3.6.1.5.5.7.3.9"
    ];

    private static final EXTENDED_KEY_USAGE_TEXTS = [
            "All Usages",
            "All Usages",
            "Server Authentication",
            "Client Authentication",
            "Code Signing",
            "Email Protection",
            "IPSec end system",
            "IPSec tunnel",
            "IPSec user",
            "Timestamping",
            "Smartcard Logon",
            "OCSP signer"
    ];

    private static final OID_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3"

    private static final OID_PSD2_QC_STATEMENT = "0.4.0.19495.2"

    private static final OID_ORGANIZATIONAL_IDENTIFIER = "2.5.4.97"
    private static final TYPE_ORGANIZATIONAL_IDENTIFIER = "OI"

    public static parseDN(String dn) {
        def result = [:]


        LdapName ln = new LdapName(dn);

        for(Rdn rdn : ln.getRdns()) {
            def rdnType = rdn.getType();
            // LdapName doesn't know about OrganizationalIdentifier
            if (rdnType == ("OID." + OID_ORGANIZATIONAL_IDENTIFIER)) {
                rdnType = TYPE_ORGANIZATIONAL_IDENTIFIER
            }
            result.put(rdnType,rdn.getValue());
        }


        return result;
    }
}

def certToObject(String certPem) {
    InputStream certStream = new ByteArrayInputStream(certPem.getBytes());
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Certificate certificate = cf.generateCertificate(certStream);
    def object = [
            subjectDNComponents:  CertificateParserHelper.parseDN(certificate.getSubjectDN().toString()),
    ]
    logger.debug(SCRIPT_NAME + "Parsed certificate " + object.toString())
    // Add the X509Certificate object after the logging of the parsed data to prevent the logs being spammed
    object.put("certificate", certificate)

    return object
}


def header = request.headers.get(routeArgCertificateHeader)

if (header == null) {
    // response object
    response = new Response(Status.BAD_REQUEST)
    response.headers['Content-Type'] = "application/json"
    message = "No certificate header on inbound request " + routeArgCertificateHeader
    logger.error(SCRIPT_NAME + message)
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

String certPem = URLDecoder.decode(header.firstValue.toString())

logger.debug(SCRIPT_NAME + "Client certificate PEM: \n" + certPem)

def certObject = certToObject(certPem)

// Store certificate details for other filters
attributes.clientCertificate = certObject

next.handle(context, request)
