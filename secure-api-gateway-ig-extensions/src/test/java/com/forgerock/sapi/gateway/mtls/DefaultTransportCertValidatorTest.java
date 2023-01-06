package com.forgerock.sapi.gateway.mtls;

import static com.forgerock.sapi.gateway.mtls.TransportCertValidationFilter.parseCertificate;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DefaultTransportCertValidatorTest {

    /**
     * Example public cert
     */
    public static final String TEST_TLS_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGWDCCBUCgAwIBAgIEWcaJ8TANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJH\n" +
            "QjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxLjAsBgNVBAMTJU9wZW5CYW5raW5nIFBy\n" +
            "ZS1Qcm9kdWN0aW9uIElzc3VpbmcgQ0EwHhcNMjIwODIyMTIzMTQ0WhcNMjMwOTIy\n" +
            "MTMwMTQ0WjBzMQswCQYDVQQGEwJHQjEaMBgGA1UEChMRRk9SR0VST0NLIExJTUlU\n" +
            "RUQxKzApBgNVBGETIlBTREdCLU9CLVVua25vd24wMDE1ODAwMDAxMDQxUkVBQVkx\n" +
            "GzAZBgNVBAMTEjAwMTU4MDAwMDEwNDFSRUFBWTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "ggEPADCCAQoCggEBAKa7CxtFxQykdmFZ0dtn6xlO8Ms4RKQhFVH6eygrS2XnNN9J\n" +
            "Cn09SXE2bCVwnWGwvn5iIn262N1WkBS1+7zVDM7/djZ8NNSxJD2fP0f0uETdrj7h\n" +
            "CyAmTXtt57edxDGDpwGOc7tfZ6HYQiIYQ4WLeJw2xHHrFffBOIok3Gb3R28cke0u\n" +
            "MVW+qZf6LX3H45Fl4VEWrV28tBMmOBkdUxiy/PReYcW7mH20OdqizVELf5Z8Flnq\n" +
            "6Z5gs3i5BE5oIDpLiXT2Drs+OVmCR4K1HgG7PZOLRsVPyZRf3hBSpFhfS4IaEQR2\n" +
            "81dwRZZyUCIvQSayqSwEz/uYcFEmGrP9PN6NV2UCAwEAAaOCAxIwggMOMA4GA1Ud\n" +
            "DwEB/wQEAwIHgDCBkQYIKwYBBQUHAQMEgYQwgYEwEwYGBACORgEGMAkGBwQAjkYB\n" +
            "BgMwagYGBACBmCcCMGAwOTARBgcEAIGYJwEBDAZQU1BfQVMwEQYHBACBmCcBAgwG\n" +
            "UFNQX1BJMBEGBwQAgZgnAQMMBlBTUF9BSQwbRmluYW5jaWFsIENvbmR1Y3QgQXV0\n" +
            "aG9yaXR5DAZHQi1GQ0EwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC\n" +
            "MIHgBgNVHSAEgdgwgdUwgdIGCysGAQQBqHWBBgFkMIHCMCoGCCsGAQUFBwIBFh5o\n" +
            "dHRwOi8vb2IudHJ1c3Rpcy5jb20vcG9saWNpZXMwgZMGCCsGAQUFBwICMIGGDIGD\n" +
            "VXNlIG9mIHRoaXMgQ2VydGlmaWNhdGUgY29uc3RpdHV0ZXMgYWNjZXB0YW5jZSBv\n" +
            "ZiB0aGUgT3BlbkJhbmtpbmcgUm9vdCBDQSBDZXJ0aWZpY2F0aW9uIFBvbGljaWVz\n" +
            "IGFuZCBDZXJ0aWZpY2F0ZSBQcmFjdGljZSBTdGF0ZW1lbnQwbQYIKwYBBQUHAQEE\n" +
            "YTBfMCYGCCsGAQUFBzABhhpodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2NzcDA1Bggr\n" +
            "BgEFBQcwAoYpaHR0cDovL29iLnRydXN0aXMuY29tL29iX3BwX2lzc3VpbmdjYS5j\n" +
            "cnQweAYDVR0RBHEwb4IlbWF0bHMucnMuYXNwc3Aub2IuZm9yZ2Vyb2NrLmZpbmFu\n" +
            "Y2lhbIIlbWF0bHMuYXMuYXNwc3Aub2IuZm9yZ2Vyb2NrLmZpbmFuY2lhbIIfcnMu\n" +
            "YXNwc3Aub2IuZm9yZ2Vyb2NrLmZpbmFuY2lhbDA6BgNVHR8EMzAxMC+gLaArhilo\n" +
            "dHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNybDAfBgNVHSME\n" +
            "GDAWgBRQc5HGIXLTd/T+ABIGgVx5eW4/UDAdBgNVHQ4EFgQUlV66Ey7k3wP1k6Qx\n" +
            "0E81D8pYbqgwDQYJKoZIhvcNAQELBQADggEBACQ2pAfVVTCmP0wTg3J7bLtp7aei\n" +
            "IglcRCTQus0TFGAnIbTeTgkOGza6GSWBjpqyGX/4m8wdeDYz6xsZw/da2253w8fB\n" +
            "RAaps/GSUvpqRY8aVL1y3rWQPjbO1xVi/gZfvWSyiMJBaDalIYJmO0fMHhl4/ckr\n" +
            "jwnponCmeTpWUdXvEVx+5kaOkoVnPuJOjqlfU2luAq7s6l3KBiJzu0tYMqnL97er\n" +
            "LleYQkFPpTksh3mB2Hk8vAuKVJd+v2ViGzB6eAsiFzsU8Yfm4ixfOih2FKdFKKUR\n" +
            "zdhiQ4NP8Ee6H13l0E+RuCoSsFEgkFiCdVDStKxLtct6nAnBSGArhoznsJ8=\n" +
            "-----END CERTIFICATE-----\n";
    /**
     * JWKSet which contains the TEST_TLS_CERT as one of its entries
     */
    public static final org.forgerock.json.jose.jwk.JWKSet TEST_JWKS = org.forgerock.json.jose.jwk.JWKSet.parse("{\n" +
            "  \"keys\" : [ \n" +
            "    {\n" +
            "    \"kid\" : \"9C0VQ80zzyxrdAjWGaIgw0Wx4HA\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"r2oPYqltDjvlDlnhbAppuvOIBmhVQJcpGHdytsoBDko-Nb-oC3xAXu4u1Dez-LbmYfLcZa7GDNOT_fYcEZ2U7epiHN60bERJWS8KNWNRNvJtCN3ozO_jJbfki9U53D43HrK2rdaSIdiGpZGe5mDUiBFAKqgedXyIWYrsgKGVHs0mGURI66vJo4NcB7BHF6gctgbpMKnPetIXxKjkbt6pBaANKdC7AXPzSAhzv9AA5kbO3fcsw1GYcEdiEdyQQ3FvnqHczQdFU6crR97MF88eNZUhRcFDKEA_aGlo7EC2CN3YLQ7aEC-YpWz8CFZiUrA_s2GlVasR4Q5VYemfZ17Hlw\",\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"use\" : \"tls\",\n" +
            "    \"x5c\" : [ \"MIIFODCCBCCgAwIBAgIEWcZTgDANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxLjAsBgNVBAMTJU9wZW5CYW5raW5nIFByZS1Qcm9kdWN0aW9uIElzc3VpbmcgQ0EwHhcNMjExMTIyMTYzMDU1WhcNMjIxMjIyMTcwMDU1WjBhMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxGzAZBgNVBAsTEjAwMTU4MDAwMDEwNDFSRUFBWTEfMB0GA1UEAxMWZWJTcVROcW1RWEZZejZWdFdHWFpBYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK9qD2KpbQ475Q5Z4WwKabrziAZoVUCXKRh3crbKAQ5KPjW/qAt8QF7uLtQ3s/i25mHy3GWuxgzTk/32HBGdlO3qYhzetGxESVkvCjVjUTbybQjd6Mzv4yW35IvVOdw+Nx6ytq3WkiHYhqWRnuZg1IgRQCqoHnV8iFmK7IChlR7NJhlESOuryaODXAewRxeoHLYG6TCpz3rSF8So5G7eqQWgDSnQuwFz80gIc7/QAOZGzt33LMNRmHBHYhHckENxb56h3M0HRVOnK0fezBfPHjWVIUXBQyhAP2hpaOxAtgjd2C0O2hAvmKVs/AhWYlKwP7NhpVWrEeEOVWHpn2dex5cCAwEAAaOCAgQwggIAMA4GA1UdDwEB/wQEAwIHgDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwgeAGA1UdIASB2DCB1TCB0gYLKwYBBAGodYEGAWQwgcIwKgYIKwYBBQUHAgEWHmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9wb2xpY2llczCBkwYIKwYBBQUHAgIwgYYMgYNVc2Ugb2YgdGhpcyBDZXJ0aWZpY2F0ZSBjb25zdGl0dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBPcGVuQmFua2luZyBSb290IENBIENlcnRpZmljYXRpb24gUG9saWNpZXMgYW5kIENlcnRpZmljYXRlIFByYWN0aWNlIFN0YXRlbWVudDBtBggrBgEFBQcBAQRhMF8wJgYIKwYBBQUHMAGGGmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9vY3NwMDUGCCsGAQUFBzAChilodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNydDA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNybDAfBgNVHSMEGDAWgBRQc5HGIXLTd/T+ABIGgVx5eW4/UDAdBgNVHQ4EFgQUovPjv8u864sAWvBrumz+EVN4vE0wDQYJKoZIhvcNAQELBQADggEBACRTRi7LmWqxclAeBc94GAVCzXxHq6ftdv6y+Dgx6A0hBKZOYABcjtbAtw6IHPzDdElPPa2IYLc+8HCuD2JLA1c2hbmnA5Mv1Tij8F4HHQu0SVgioKZF3FQ6P5NLMA3wn4Ayl7RM9wBAMPIsldXp8VC/Y5zmGSEAxu1HPvpamm8PiMd4ONI56rl7wyLlaiv4ubG/bLQFnkjz2FHkKE/1faOxlI8e0E2015CtE7Cl+xKV/mkA6elTv8raN/4c3HYBGU4jwrzesgjOPNNJ9sPYUkIKbs2vZJq3EXzvBMGbKV9clcdbf6Troeg2OqB7Kc6IlaGT6/qpF5bWL4NLk+GZdYc=\" ],\n" +
            "    \"x5t\" : \"8bNh42B2L4UBhLCSwyrm0eItdlU=\",\n" +
            "    \"x5u\" : \"https://keystore.openbankingtest.org.uk/0015800001041REAAY/9C0VQ80zzyxrdAjWGaIgw0Wx4HA.pem\",\n" +
            "    \"x5t#S256\" : \"5uV6WSJr4MiiY-Dn7hZElwdnonEBqSkOqNAWE4bvMf0=\"\n" +
            "  }, {\n" +
            "    \"kid\" : \"O8vc_bkNug8CH2wcnAO_s_d8IFI\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"prsLG0XFDKR2YVnR22frGU7wyzhEpCEVUfp7KCtLZec030kKfT1JcTZsJXCdYbC-fmIifbrY3VaQFLX7vNUMzv92Nnw01LEkPZ8_R_S4RN2uPuELICZNe23nt53EMYOnAY5zu19nodhCIhhDhYt4nDbEcesV98E4iiTcZvdHbxyR7S4xVb6pl_otfcfjkWXhURatXby0EyY4GR1TGLL89F5hxbuYfbQ52qLNUQt_lnwWWerpnmCzeLkETmggOkuJdPYOuz45WYJHgrUeAbs9k4tGxU_JlF_eEFKkWF9LghoRBHbzV3BFlnJQIi9BJrKpLATP-5hwUSYas_083o1XZQ\",\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"use\" : \"tls\",\n" +
            "    \"x5c\" : [ \"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\" ],\n" +
            "    \"x5t\" : \"LO4q2Lc9uYpfXT7hwdU310KiI3E=\",\n" +
            "    \"x5u\" : \"https://keystore.openbankingtest.org.uk/0015800001041REAAY/O8vc_bkNug8CH2wcnAO_s_d8IFI.pem\",\n" +
            "    \"x5t#S256\" : \"Ts363RPCiz-KLDE4WMETiRBoOfTPIR-fIlCkRXC7MHs=\"\n" +
            "  }\n" +
            " ]\n" +
            "}");

    public static final String TLS_KEY_USE = "tls";

    @Test
    void testValidCertAndUse() throws CertificateException {
        new DefaultTransportCertValidator(TLS_KEY_USE).validate(parseCertificate(TEST_TLS_CERT), TEST_JWKS);
    }

    @Test
    void testValidCertNoUseCheck() throws CertificateException {
        new DefaultTransportCertValidator().validate(parseCertificate(TEST_TLS_CERT), TEST_JWKS);
    }

    @Test
    void failsWhenCertMatchButUseDoesNot() throws CertificateException {
        final X509Certificate certificate = parseCertificate(TEST_TLS_CERT);
        final CertificateException certificateException = Assertions.assertThrows(CertificateException.class,
                () -> new DefaultTransportCertValidator("blah").validate(certificate, TEST_JWKS));

        Assertions.assertEquals("Failed to find JWK entry in provided JWKSet which matches the X509 cert", certificateException.getMessage());
    }
}