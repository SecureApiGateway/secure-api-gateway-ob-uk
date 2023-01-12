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
package com.forgerock.sapi.gateway.dcr.request;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.request.DCRRequestValidationException.ErrorCode;
import com.forgerock.sapi.gateway.jwks.RestJwkSetServiceTest;
import com.forgerock.sapi.gateway.jwks.mocks.MockJwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryOpenBankingTest;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectorySecureApiGateway;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryServiceStatic;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

class RequestAndSsaSignatureValidationFilterTest {


    private Request request;
    private Handler handler = mock(Handler.class);
    private static RequestAndSsaSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier registrationObjectSupplier;
    private static RSASSASigner RSA_SIGNER;
    final private static JwtSignatureValidator jwtSignatureValidator = mock(JwtSignatureValidator.class);
    private MockJwkSetService jwkSetService;
    final private static String DIRECTORY_JWKS_URI = "https://keystore.openbankingtest.org.uk/keystore/openbanking.jwks";
    final private static String SOFTWARE_STATEMENT_JWKS_URI = "https://directory.softwareid.jwks_uri";
    final private static String JWKS = "{\n" +
            "    \"keys\": [\n" +
            "      {\n" +
            "        \"d\": \"N--FZgR47kIISyVhHmOjPfvxw7yLnCxdxKVH8dMRTiC3cjDBhri6fxXBAY4SgXWgQhwuy20wrO6vKBGNBZA3prCKg34ttxC9ldrstrEiGHhYPSO-zaOdYjozaash94Vzm0ZhbBvm6hfZhhP_fqf4lZk9V0mSfdkBtEEK0Q_Xz_MsxOnRtDetVmCAeeBbSLx-j3uIO5divh6uMRvyfScS92xO0sXtSgOoBhSLypLxCCEzJfAJObGIcBCktBZKdtPoySkHTk0r1OUfLOEH4VNsDNdOdoR25miPWQqrWy_BHRKH-IlsfLeOCFLqfC5DgWhxLUJEG9OkNdgPdW-YUIZ25Q\",\n" +
            "        \"e\": \"AQAB\",\n" +
            "        \"use\": \"tls\",\n" +
            "        \"kid\": \"101824185923205669603949338071238433498\",\n" +
            "        \"x5c\": [\n" +
            "          \"MIIFfzCCA2egAwIBAgIQTJqf97E+pMEckV7e4Zfa2jANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtUZXN0IFNlY3VyZSBCYW5raW5nIFJvb3QgQ0EwHhcNMjMwMTExMTEzMDA2WhcNMjQwMTExMTEzMDA2WjBEMRUwEwYDVQQDDAxBY21lIEZpbnRlY2gxKzApBgNVBGEMIlBTREdCLUZGQS01ZjU2M2U4OTc0MmIyODAwMTQ1YzdkYTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxz8aNWATaDwTwJTSQxQHgY1W0vjL7T+w+i9Z9kDJhENniVnUszGDHE4b5Fz1XcAfxmfqRneSFrRD9a3dTKtxa6+FhJ6UFnK6+Jsk9zg4jaDIVsVYJoOi40CIe9oPRLgatVQLIBVoklAiXgltpUpV2AUpniKrnVt8kGZfCMfck2sEPhMHRJCvFrLCXPcxLPrsKDOIURnywc5w8+1i+2558Rrb+qwSOoUSvRUe4WJxxPGBTNTsjjEv+zH2R+9tCMrxCGu4U4Ds2JDw51nx/jpg9lQMseKroGAsZJGJ6w9KkaD1kg06SQlT7pD2RdI0AXvUmODiQBpFuH1o+/rvEghKbAgMBAAGjggGJMIIBhTAMBgNVHRMBAf8EAjAAMFYGA1UdIwRPME2AFGAtnQoPDZDO/Lsfe6WGHY6l4LVUoSqkKDAmMSQwIgYDVQQDDBtUZXN0IFNlY3VyZSBCYW5raW5nIFJvb3QgQ0GCCQDzZXhgPta6gDAdBgNVHQ4EFgQU0/HeXsNJ4YVYb3bUcxfl5x8w3sEwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMIHbBggrBgEFBQcBAwSBzjCByzAIBgYEAI5GAQEwEwYGBACORgEGMAkGBwQAjkYBBgMwCQYHBACL7EkBAjCBngYGBACBmCcCMIGTMGowKQYHBACBmCcBBAweQ2FyZCBCYXNlZCBQYXltZW50IEluc3RydW1lbnRzMB4GBwQAgZgnAQMME0FjY291bnQgSW5mb3JtYXRpb24wHQYHBACBmCcBAgwSUGF5bWVudCBJbml0aWF0aW9uDB1Gb3JnZVJvY2sgRmluYW5jaWFsIEF1dGhvcml0eQwGR0ItRkZBMA0GCSqGSIb3DQEBCwUAA4ICAQCOOdurJCSqcvwvB8f0wVrMQ+cijJWbjadQVA23k5ydAM50TN/OXJ/E5j7HqP6n9CdRvwD8b5CYLmb+K4vxEVtfPXjrkWD5cELV4ai3Uz5O0YLvtWFX2bh0yqEJrUNpOTE1t/2WBvlvMyhj2a1AtE92g8W7cYXTBYiGaYupsw8YqYkDm2g+Mfo+ss8SlGHcDY8TKhlToNaFDNYJ/aLvTIn/ifnXvrOCvatboa5vWls7Pvaq4T2RcwefRUI8Z1NyagAYZqXdNtGFgwkq5kNVDFeFabCkDvqCKxnW7dP074Nb3gkIn/1Se28vNR619KE3MW5ZXMr9DE1RGl4ZZVAzgvwQn3asWxd7mwhfkDeniOV5hAnkuuWRc19nWvQ7obifXjS3m/TsHkdWQQPuGu99bzYhhcL3vy37VvKjbXd217MhlL6Vs0TgqysA9OrVSNy9vOgNWOb9NZLvOSsdE3pHACmqaSiGOV59u9arAIhryyIr7pNXaoWP70zd1I5177KRaq2pE1hx4BYdkHxSZDT5XfK7VlNhGF/FqugUVEazERYYTTgDYchp0Kwl+dUM2CpGiTj2veKUBqH/SGOnJ+igpVcXuqzzqC5ufqr2vdPqhTXo4n9OsKJJ4z6NG12JL5sggBUb2aRg4R+hS26KaH9EOkI4UAPOwLiBBwLCpI7xQfvNZA==\"\n" +
            "        ],\n" +
            "        \"dp\": \"2AWfEVzU5BBzG6IwkYj9o4fIG7YTGz3XP6Rq5riVF2WR_SooTqivZjEnmWJrMScKFZzKmIqEmTyJmzk7Dj-fQ3o0isenkTbmfCS45VMxEP2WtBetrowlnZrQBir0nnxyIzY3gZGbEo3pEek6nXzGaH6Wyy8tqh99MnC67ZK5uw\",\n" +
            "        \"dq\": \"JF6IuJoQWyZQIx9po1iLC-7vHH_OU1mUh2FfEqTT68uwR6KWoWU1GivLGn76joDyiBN3g5RzXzVX72OHk3YgqnVHcToDfPPiwklWB2b3U4FWt_wvLVlcVxzAmlZJS7twF009SPbuuAIXzQi9-YU2nCajTQoizdNbOEHYnlQ5IFE\",\n" +
            "        \"n\": \"sc_GjVgE2g8E8CU0kMUB4GNVtL4y-0_sPovWfZAyYRDZ4lZ1LMxgxxOG-Rc9V3AH8Zn6kZ3kha0Q_Wt3UyrcWuvhYSelBZyuvibJPc4OI2gyFbFWCaDouNAiHvaD0S4GrVUCyAVaJJQIl4JbaVKVdgFKZ4iq51bfJBmXwjH3JNrBD4TB0SQrxaywlz3MSz67CgziFEZ8sHOcPPtYvtuefEa2_qsEjqFEr0VHuFiccTxgUzU7I4xL_sx9kfvbQjK8QhruFOA7NiQ8OdZ8f46YPZUDLHiq6BgLGSRiesPSpGg9ZINOkkJU-6Q9kXSNAF71Jjg4kAaRbh9aPv67xIISmw\",\n" +
            "        \"p\": \"2N9WbWlPkHXM-Q5ajkfXA4j0mBZFFmdZ11L9iKwn9_Kb_rrgWSooNxelb_n-kiRfnEMjWK3K7q_Sqm1DiwWzNk_HzMj7VDKqXWidp7PKLl0EtmTGjMaaxITyk46JUsPUdBx3LvgUuOHdfU-cIto-I2hnsXdwSZa-D_3rSZc-jEc\",\n" +
            "        \"kty\": \"RSA\",\n" +
            "        \"x5t#S256\": \"L-xaRjtynLMe5T-G63JJvZ2iRHenhRrzJSVA15CBHGE\",\n" +
            "        \"q\": \"0eRXcqwSJuyv3nIV4krOmJ3e5NVpe5_fjzymur7F2kyO6IeUmqRw4c_3fDbwV-g3v-6teHhEQMKSujHAfulHhSN7DUnG_NRwrK7C-ESApE84v5ePrfR--UL9588HK0ykiVzkGJ8817YN3e1P2o9gmwjqK8QfMufyjjnpGaDD9Q0\",\n" +
            "        \"qi\": \"E8fBuffMaXF6RllFqtQJhyCYGJlH0-cj7AMF0R63L8f65KIA6fTEcTEI1BmarW9pqKTP7T3uMjjrQrjc37rfHIz3DWzRywNudEa8xwBSpAPLEIzhnW8CWkTI-0-PDTzzPBUpWcCCXqvCugGW_T2Rftsq6MpNm0_1Om7VCJoKyxY\",\n" +
            "        \"alg\": \"PS256\"\n" +
            "      },\n" +
            "      {\n" +
            "        \"d\": \"KvnfP6tKwx9TODjyp_8lEiuKBULe4hXYOBB41V0jqfOHhT_8jmcu7NH5h_bJFxEFly7kl5s9Bbe0FOM5hagdaAtoWyBK0_dDg5CAHhZ2ot7IvkNmzMt2XCEIJJUGg4GOZH4Pr8JZp4xFJzfS-JG-2d4zNqvaAn_ztjxI4r9cfZK9Xy2DKI5fx5n5bXhoEle30z-Uf8Pwd9oBJvh5i3ot7af7JDGxkoA78EyYW8TnssQRbp2hvoe6wp2xNgCCj8LQjRteF7Qgt4iRDoQZC4CY87r-N0-poiBJwAO8Yi-qzYonWoNX3T47VtsVl9Lv4uZ2KwP-v04VNIACxRW-NLvQtQ\",\n" +
            "        \"e\": \"AQAB\",\n" +
            "        \"use\": \"sig\",\n" +
            "        \"kid\": \"250029841938361220893822773219797310071\",\n" +
            "        \"x5c\": [\n" +
            "          \"MIIFgDCCA2igAwIBAgIRALwZ/vcZplK3chDRLOsNGncwDQYJKoZIhvcNAQELBQAwJjEkMCIGA1UEAwwbVGVzdCBTZWN1cmUgQmFua2luZyBSb290IENBMB4XDTIzMDExMTExMzAwNVoXDTI0MDExMTExMzAwNVowRDEVMBMGA1UEAwwMQWNtZSBGaW50ZWNoMSswKQYDVQRhDCJQU0RHQi1GRkEtNWY1NjNlODk3NDJiMjgwMDE0NWM3ZGExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu6Y4xWnuzDYbZquuqN3hgm2WUYZyACp5a008WXDD7BlewAYI0xQ1URLGpgtTddlyqVsd+/RyZJc/e8VnLWwO+k8G0qsEtAsT0xM5ncBGSvwYnMeskOk92JuN2waX/m6bBYZ64mrPlc8UJIzieXePbLk2BbKhEISYjQSQg8/a+HsBHwtuSlCgkQkPfyyno5kJARz7ev1xOOmzMqPyYWgeKZK7HN5fGlYltrUu7KxuFMa3KKPsJx+sXNzHH631J9SXVPXZsXbPYgakK+ICRTd347W01o2bf05zNeFdqvwJFdqaOgcgelAYj+CmXKepTvZd1wfFB6uF/LE0EwYwk5HyBwIDAQABo4IBiTCCAYUwDAYDVR0TAQH/BAIwADBWBgNVHSMETzBNgBRgLZ0KDw2Qzvy7H3ulhh2OpeC1VKEqpCgwJjEkMCIGA1UEAwwbVGVzdCBTZWN1cmUgQmFua2luZyBSb290IENBggkA82V4YD7WuoAwHQYDVR0OBBYEFHo/yKduUZWl0OvNSCfHIcqbgrtOMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjCB2wYIKwYBBQUHAQMEgc4wgcswCAYGBACORgEBMBMGBgQAjkYBBjAJBgcEAI5GAQYCMAkGBwQAi+xJAQIwgZ4GBgQAgZgnAjCBkzBqMCkGBwQAgZgnAQQMHkNhcmQgQmFzZWQgUGF5bWVudCBJbnN0cnVtZW50czAeBgcEAIGYJwEDDBNBY2NvdW50IEluZm9ybWF0aW9uMB0GBwQAgZgnAQIMElBheW1lbnQgSW5pdGlhdGlvbgwdRm9yZ2VSb2NrIEZpbmFuY2lhbCBBdXRob3JpdHkMBkdCLUZGQTANBgkqhkiG9w0BAQsFAAOCAgEAiNG5fqT14L5eCIvd0MA6BqI1LnYhOIWOndqXymBm6AZII4XDQlAw4fgiItPzGi9SqYVoL6LULiWzRHFSECY0v/zi7Im/C+7q6pyXEd4sZz7fwZS+GpG7up0VJPCpGNot02yGqgvH9LujyQwULmjTq2mR5l+k4lHNbPFdXIvkv5NinEr/9ki752j6pmLf4rr+za1t02Kf/zuB0WjNdOSEBrY7d2oRH0aP1hfGfoj13MuKmNMFO0vV+hwxR8wV/La3IyxrSbsPQeHuRFVfQT+VictJbIp49WdhuYeX5KjyT8wIjpMwofEJ/64nmBZ+fvOoH7Kju0DnQWqTwvKdLlhqh1I2w3jOgH8lEjFNZ17pnXe/QMO9vM2xx07V5qUKxnMkMhEc1SNvKPh6nghK4truZgiM71J6++06L3JRyGE69MZ/V6PFMJflZtBsKh4oe+Lus/emG+Mz4kMQviTGZZ8RvnezIU6oxsX75tiungreSgq0r+GsnhPMUiTkwNRfX5jPUFhxLZtbVvJaBTVt7AObuFv/l9Bm1aLJAipTTLMtydFQva8L7P3MDFnSDGqrWfMKYyzm3lMoBA25oWxIfb+Esm8AbE8PdrRWkKxaGOB3LJ/xnp6KPSXb0yan0ABum3CY2EmJLTWl33DElxJ68umOPo4GdeZGnhoZq45c3hfTO6Y=\"\n" +
            "        ],\n" +
            "        \"dp\": \"yIlfCTcBKBU_68yRMOroo8uMKj7IySvCi0N2oLJH9A9A0biTjYF1NvEUyM34GDVvO8eLyHEugoI9ButcGYFuO86TeIn5V7xkUQLC2z-YjgawoeRIKyOtp2HzMc37fnV8evi44OWfb5wO4YZ6tUW8A-jkHhTGYAsZVe1WrVIk1_E\",\n" +
            "        \"dq\": \"okO-cz59GiY4mu3Z90ozRUYzO9HyIqS2sMEX_4vJS9yfDLPkNowhx2OkRyONDLcgCchyPn6IDnXSNA9OZml_9_Vs4LNj3mNqKw1qgiz36QZU7i1Gy4zREKCUdbkFUgp_7mTQwATrq6Er9KRsf6-4tusiRUorqpfRKqzKwJyCmiU\",\n" +
            "        \"n\": \"u6Y4xWnuzDYbZquuqN3hgm2WUYZyACp5a008WXDD7BlewAYI0xQ1URLGpgtTddlyqVsd-_RyZJc_e8VnLWwO-k8G0qsEtAsT0xM5ncBGSvwYnMeskOk92JuN2waX_m6bBYZ64mrPlc8UJIzieXePbLk2BbKhEISYjQSQg8_a-HsBHwtuSlCgkQkPfyyno5kJARz7ev1xOOmzMqPyYWgeKZK7HN5fGlYltrUu7KxuFMa3KKPsJx-sXNzHH631J9SXVPXZsXbPYgakK-ICRTd347W01o2bf05zNeFdqvwJFdqaOgcgelAYj-CmXKepTvZd1wfFB6uF_LE0EwYwk5HyBw\",\n" +
            "        \"p\": \"8nuYjeCJFU3DeMkB1vItfPpepLkXDJqs8RpYg7A8o38FjyPO6C5DTHiEX4k0g48hckJP9H-sgqrdsh_7L7ZHQFWenxEgPVDhkezSr2oB9CGy4a5arwFJ2Sd18qEbTW2X3S-XOiVCMB44vj1sFer_QIYaQaNyBebNotnu-JkLHnM\",\n" +
            "        \"kty\": \"RSA\",\n" +
            "        \"x5t#S256\": \"iSmkgO0nhQBYU2E18peCW6EoqrLQohkKfYnP7kpuL8E\",\n" +
            "        \"q\": \"xhwcyAoJK1Lu7WhRjpAuizd9pEvH1414zaRjrVJwD_nfDUlR0Nq7Kln9u8-MBFmpmRNn0qPeWqGW6GLKBG9Nh00Mc-PiWEDcvo1CI_ws9BLbVThI4Coavg5cMo82En5heZT8sIChY330V-y9AlVIZKCIgzCzpU760X8UR7RbxR0\",\n" +
            "        \"qi\": \"3MimDkb9jLDaIIIN0KqS0Qxz-u_1UJ-LfoDE0Pxdwla8dWBqs3Vm2fuHUvTFRvVVgKHxgR9O-xluQXYBcQlLXwS5Ag4tZkDjP4kGU-ULLQuT4zX593Rw9sVOVVEFNZT9gHW7zqfWFH-TgI5RroSx7zakolZtevpdleNsWhQKbmc\",\n" +
            "        \"alg\": \"PS256\"\n" +
            "      }\n" +
            "    ]\n" +
            "  }";

    @BeforeAll
    public static void beforeAll() throws NoSuchAlgorithmException {
        RSA_SIGNER = createRSASSASigner();
    }

    /**
     * JWT signer which uses generated test RSA private key
     */
    private static RSASSASigner createRSASSASigner() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new RSASSASigner(pair.getPrivate());
    }

    @BeforeEach
    void setUp() throws MalformedURLException {
        registrationObjectSupplier = mock(RequestAndSsaSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier.class);
        handler = mock(Handler.class);
        Map<URL, JWKSet> jwkSetByUrl = new HashMap();
        jwkSetByUrl.put(new URL(DIRECTORY_JWKS_URI), createJwkSet());
        jwkSetByUrl.put(new URL(SOFTWARE_STATEMENT_JWKS_URI), createJwkSet());
        jwkSetService = new MockJwkSetService(jwkSetByUrl);
        this.request = new Request().setMethod("POST");
    }

    @AfterEach
    void tearDown() {
        reset(handler,  registrationObjectSupplier);
    }

    private TrustedDirectoryService getTrustedDirectory(boolean sapigDirectoryEnabled) {
        return new TrustedDirectoryServiceStatic(sapigDirectoryEnabled, DIRECTORY_JWKS_URI);
    }

    private JWKSet createJwkSet() {
        return new JWKSet(List.of(RestJwkSetServiceTest.createJWK(UUID.randomUUID().toString()),
                RestJwkSetServiceTest.createJWK(UUID.randomUUID().toString())));
    }

    /**
     * Uses nimbusds to create a SignedJWT and returns JWS object in its compact format consisting of
     * Base64URL-encoded parts delimited by period ('.') characters.
     *
     * @param claims      The claims to include in the signed jwt
     * @param signingAlgo the algorithm to use for signing
     * @return the jws in its compact form consisting of Base64URL-encoded parts delimited by period ('.') characters.
     */
    private String createEncodedJwtString(Map<String, Object> claims, JWSAlgorithm signingAlgo) {
        try {
            final SignedJWT signedJWT = new SignedJWT(new JWSHeader(signingAlgo), JWTClaimsSet.parse(claims));
            signedJWT.sign(RSA_SIGNER);
            return signedJWT.serialize();
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private SignedJwt createSignedJwt(Map<String, Object> claims, JWSAlgorithm signingAlgo) {
        String encodedJwsString = createEncodedJwtString(claims, signingAlgo);
        return new JwtReconstruction().reconstructJwt(encodedJwsString, SignedJwt.class);
    }

    @Test
    void filter_successSoftwareStatementWithJwskUri() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        Map<String, Object> ssaClaimsMap = Map.of("iss", "OpenBanking Ltd",
                TrustedDirectoryOpenBankingTest.softwareJwksUriClaimName, SOFTWARE_STATEMENT_JWKS_URI);
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        // When

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assert(response.getStatus()).isSuccessful();
        verify(handler, times(1)).handle(null, request);
    }

    @Test
    @Disabled
    void filter_successSoftwareStatementWithJwsk() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        Map<String, Object> ssaClaimsMap = Map.of("iss", "test-publisher",
                TrustedDirectorySecureApiGateway.softwareStatementJwksClaimName, JWKS);
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        // When

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assert(response.getStatus()).isSuccessful();
        verify(handler, times(1)).handle(null, request);
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenNoRegistrationRequestJwt() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                DCRRequestValidationException.ErrorCode.INVALID_CLIENT_METADATA.toString());
        assertThat(responseBody.get("error_description")).contains("Requests to registration endpoint must contain a " +
                "signed request jwt");
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenNoSoftwareStatement() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        SignedJwt signedJwt = createSignedJwt(Map.of(), JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.INVALID_CLIENT_METADATA.toString());
        assertThat(responseBody.get("error_description")).contains("registration request jwt must contain " +
                "'software_statement' claim");
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenSoftwareStatementHasNoIssuer() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        String encodedSsaJwtString = createEncodedJwtString(Map.of(), JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.INVALID_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("registration request's 'software_statement' jwt " +
                "must contain an issuer claim");
    }

    @Test
    void filter_ResponseIsUnapprovedSoftwareStatementWhenSoftwareStatementHasInvalidIssuer() throws ExecutionException,
            InterruptedException, TimeoutException, IOException {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);
        String encodedSsaJwtString = createEncodedJwtString(Map.of("iss", "InvalidIssuer"), JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.UNAPPROVED_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("SSA was not issued by a Trusted Directory");
    }

    @Test
    void filter_throwsInvalidSoftwareStatementWhenSoftwareStatementHasNoJwskUri() throws IOException, ExecutionException,
            InterruptedException, TimeoutException {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        String encodedSsaJwtString = createEncodedJwtString(Map.of("iss", "OpenBanking Ltd"),
                JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);
        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).contains(ErrorCode.INVALID_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("must contain a claim for the JWKS URI");
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenSoftwareStatementHasBadlyFormedJwskUri() throws Exception {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        Map<String, Object> ssaClaimsMap = Map.of("iss", "OpenBanking Ltd",
                TrustedDirectoryOpenBankingTest.softwareJwksUriClaimName, "not a url");
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.INVALID_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("must be a valid URL");
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenSoftwareStatementHasNonHttpsJwskUri() throws IOException,
            ExecutionException, InterruptedException, TimeoutException {
        // Given
        TrustedDirectoryService trustedDirectoryService = getTrustedDirectory(true);
        RequestAndSsaSignatureValidationFilter filter = new RequestAndSsaSignatureValidationFilter(
                trustedDirectoryService, registrationObjectSupplier, List.of("PS256"), jwkSetService,
                jwtSignatureValidator);

        Map<String, Object> ssaClaimsMap = Map.of("iss", "OpenBanking Ltd",
                TrustedDirectoryOpenBankingTest.softwareJwksUriClaimName, "http://google.co.uk");
        String encodedSsaJwtString = createEncodedJwtString(ssaClaimsMap, JWSAlgorithm.PS256);
        Map<String, Object> registrationRequestJwtClaims = Map.of("software_statement", encodedSsaJwtString);
        SignedJwt signedJwt = createSignedJwt(registrationRequestJwtClaims, JWSAlgorithm.PS256);

        when(registrationObjectSupplier.apply(any(), any())).thenReturn(signedJwt);

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get(1, TimeUnit.SECONDS);

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        Map<String, String> responseBody = (Map)response.getEntity().getJson();
        assertThat(responseBody.get("error_code")).isEqualTo(
                ErrorCode.INVALID_SOFTWARE_STATEMENT.toString());
        assertThat(responseBody.get("error_description")).contains("must contain an HTTPS URI");
    }
}