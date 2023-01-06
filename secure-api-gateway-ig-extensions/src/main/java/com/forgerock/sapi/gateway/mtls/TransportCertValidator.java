package com.forgerock.sapi.gateway.mtls;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.json.jose.jwk.JWKSet;

/**
 * Validator which tests if a certificate belongs to a JWKSet and may be used for MTLS purposes.
 */
public interface TransportCertValidator {

    /**
     * validate the certificate
     *
     * @param certificate X509Certificate MTLS certificate of the client to validate
     * @param jwkSet JWKSet containing the client's keys
     * @throws CertificateException if the certificate is not a valid MTLS certificate for this client.
     */
    void validate(X509Certificate certificate, JWKSet jwkSet) throws CertificateException;

}
