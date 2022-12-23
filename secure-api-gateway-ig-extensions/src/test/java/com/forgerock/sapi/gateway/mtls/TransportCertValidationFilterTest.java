/*
 * Copyright © 2020-2022 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.mtls;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.EcJWK;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.openig.filter.finance.FapiInteractionIdFilter;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.ApiClient;
import com.forgerock.sapi.gateway.dcr.FetchApiClientFilter;
import com.forgerock.sapi.gateway.fapi.v1.FAPIAdvancedDCRValidationFilter.CertificateFromHeaderSupplier;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

class TransportCertValidationFilterTest {

    final String certString = "-----BEGIN%20CERTIFICATE-----%0AMIIGWDCCBUCgAwIBAgIEWcaJ8TANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJH%0AQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxLjAsBgNVBAMTJU9wZW5CYW5raW5nIFBy%0AZS1Qcm9kdWN0aW9uIElzc3VpbmcgQ0EwHhcNMjIwODIyMTIzMTQ0WhcNMjMwOTIy%0AMTMwMTQ0WjBzMQswCQYDVQQGEwJHQjEaMBgGA1UEChMRRk9SR0VST0NLIExJTUlU%0ARUQxKzApBgNVBGETIlBTREdCLU9CLVVua25vd24wMDE1ODAwMDAxMDQxUkVBQVkx%0AGzAZBgNVBAMTEjAwMTU4MDAwMDEwNDFSRUFBWTCCASIwDQYJKoZIhvcNAQEBBQAD%0AggEPADCCAQoCggEBAKa7CxtFxQykdmFZ0dtn6xlO8Ms4RKQhFVH6eygrS2XnNN9J%0ACn09SXE2bCVwnWGwvn5iIn262N1WkBS1%2B7zVDM7%2FdjZ8NNSxJD2fP0f0uETdrj7h%0ACyAmTXtt57edxDGDpwGOc7tfZ6HYQiIYQ4WLeJw2xHHrFffBOIok3Gb3R28cke0u%0AMVW%2BqZf6LX3H45Fl4VEWrV28tBMmOBkdUxiy%2FPReYcW7mH20OdqizVELf5Z8Flnq%0A6Z5gs3i5BE5oIDpLiXT2Drs%2BOVmCR4K1HgG7PZOLRsVPyZRf3hBSpFhfS4IaEQR2%0A81dwRZZyUCIvQSayqSwEz%2FuYcFEmGrP9PN6NV2UCAwEAAaOCAxIwggMOMA4GA1Ud%0ADwEB%2FwQEAwIHgDCBkQYIKwYBBQUHAQMEgYQwgYEwEwYGBACORgEGMAkGBwQAjkYB%0ABgMwagYGBACBmCcCMGAwOTARBgcEAIGYJwEBDAZQU1BfQVMwEQYHBACBmCcBAgwG%0AUFNQX1BJMBEGBwQAgZgnAQMMBlBTUF9BSQwbRmluYW5jaWFsIENvbmR1Y3QgQXV0%0AaG9yaXR5DAZHQi1GQ0EwIAYDVR0lAQH%2FBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC%0AMIHgBgNVHSAEgdgwgdUwgdIGCysGAQQBqHWBBgFkMIHCMCoGCCsGAQUFBwIBFh5o%0AdHRwOi8vb2IudHJ1c3Rpcy5jb20vcG9saWNpZXMwgZMGCCsGAQUFBwICMIGGDIGD%0AVXNlIG9mIHRoaXMgQ2VydGlmaWNhdGUgY29uc3RpdHV0ZXMgYWNjZXB0YW5jZSBv%0AZiB0aGUgT3BlbkJhbmtpbmcgUm9vdCBDQSBDZXJ0aWZpY2F0aW9uIFBvbGljaWVz%0AIGFuZCBDZXJ0aWZpY2F0ZSBQcmFjdGljZSBTdGF0ZW1lbnQwbQYIKwYBBQUHAQEE%0AYTBfMCYGCCsGAQUFBzABhhpodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2NzcDA1Bggr%0ABgEFBQcwAoYpaHR0cDovL29iLnRydXN0aXMuY29tL29iX3BwX2lzc3VpbmdjYS5j%0AcnQweAYDVR0RBHEwb4IlbWF0bHMucnMuYXNwc3Aub2IuZm9yZ2Vyb2NrLmZpbmFu%0AY2lhbIIlbWF0bHMuYXMuYXNwc3Aub2IuZm9yZ2Vyb2NrLmZpbmFuY2lhbIIfcnMu%0AYXNwc3Aub2IuZm9yZ2Vyb2NrLmZpbmFuY2lhbDA6BgNVHR8EMzAxMC%2BgLaArhilo%0AdHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNybDAfBgNVHSME%0AGDAWgBRQc5HGIXLTd%2FT%2BABIGgVx5eW4%2FUDAdBgNVHQ4EFgQUlV66Ey7k3wP1k6Qx%0A0E81D8pYbqgwDQYJKoZIhvcNAQELBQADggEBACQ2pAfVVTCmP0wTg3J7bLtp7aei%0AIglcRCTQus0TFGAnIbTeTgkOGza6GSWBjpqyGX%2F4m8wdeDYz6xsZw%2Fda2253w8fB%0ARAaps%2FGSUvpqRY8aVL1y3rWQPjbO1xVi%2FgZfvWSyiMJBaDalIYJmO0fMHhl4%2Fckr%0AjwnponCmeTpWUdXvEVx%2B5kaOkoVnPuJOjqlfU2luAq7s6l3KBiJzu0tYMqnL97er%0ALleYQkFPpTksh3mB2Hk8vAuKVJd%2Bv2ViGzB6eAsiFzsU8Yfm4ixfOih2FKdFKKUR%0AzdhiQ4NP8Ee6H13l0E%2BRuCoSsFEgkFiCdVDStKxLtct6nAnBSGArhoznsJ8%3D%0A-----END%20CERTIFICATE-----%0A";
    final org.forgerock.json.jose.jwk.JWKSet testJwks = org.forgerock.json.jose.jwk.JWKSet.parse("{\n" +
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

    @Disabled
    @Test
    public void testValidCert() throws ExecutionException, InterruptedException, TimeoutException {
        final String certificateHeaderName = "ssl-client-cert";
        final String jwksUrl = "https://test.jwks";
        final TransportCertValidationFilter transportCertValidationFilter = new TransportCertValidationFilter(new JwkSetService() {
            @Override
            public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URL jwkStoreUrl) {
                if (jwkStoreUrl.toString().equals(jwksUrl)) {
                    return Promises.newResultPromise(testJwks);
                } else {
                    return Promises.newExceptionPromise(new FailedToLoadJWKException("unexpected jwkStoreUrl, expected: " + jwksUrl + " got: " + jwkStoreUrl));
                }
            }

            @Override
            public Promise<JWK, FailedToLoadJWKException> getJwk(URL jwkStoreUrl, String keyId) {
                return Promises.newExceptionPromise(new FailedToLoadJWKException("getJwk should not be called by this test"));
            }
        }, new CertificateFromHeaderSupplier(certificateHeaderName));

        final AttributesContext context = new AttributesContext(new TransactionIdContext(null, new TransactionId("1234")));

        final ApiClient apiClient = new ApiClient();
        apiClient.setJwksUri(URI.create(jwksUrl));
        context.getAttributes().put(FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient);
        final Request request = new Request().setMethod("GET");
        request.addHeaders(new GenericHeader(certificateHeaderName, certString));

        final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(context, request,(ctx, req) -> Promises.newResultPromise(new Response(Status.OK)));
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        Assertions.assertEquals(200, response.getStatus().getCode(), "HTTP Response Code");
    }
}