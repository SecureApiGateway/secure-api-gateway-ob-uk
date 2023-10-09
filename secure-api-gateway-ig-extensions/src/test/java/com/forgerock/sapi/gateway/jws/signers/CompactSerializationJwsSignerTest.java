package com.forgerock.sapi.gateway.jws.signers;

import static java.util.Collections.singleton;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.secrets.keys.KeyUsage.SIGN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.forgerock.http.util.Json;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretBuilder;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;

import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public abstract class CompactSerializationJwsSignerTest {

    protected static final String KID = "xcJeVytTkFL21lHIUVkAd6QVi4M";
    protected static final String AUD = "7umx5nTR33811QyQfi";
    protected static final String JTI = UUID.randomUUID().toString();
    protected static final String TXN = UUID.randomUUID().toString();
    protected static final String ASPSP_ORG_ID = "0015800001041REAAY";
    protected static final String ALGORITHM = "PS256";
    protected final Map<String, Object> critClaims;
    protected static final String SIGNING_KEY_ID = KID;
    protected final KeyPair keyPair;
    protected final RSASSAVerifier rsaJwtVerifier;

    public CompactSerializationJwsSignerTest() {
        keyPair = CryptoUtils.generateRsaKeyPair();
        rsaJwtVerifier = new RSASSAVerifier((RSAPublicKey) keyPair.getPublic());
        long iat = System.currentTimeMillis() / 1000;
        this.critClaims = Map.of(
                "http://openbanking.org.uk/iat", iat,
                "http://openbanking.org.uk/iss", ASPSP_ORG_ID,
                "http://openbanking.org.uk/tan", "openbanking.org.uk"
        );
    }

    protected SigningKey getSigningKey(String signingKeyId) throws Exception {
        return new SecretBuilder().secretKey(keyPair.getPrivate())
                .stableId(signingKeyId)
                .keyUsages(singleton(SIGN))
                .expiresAt(Instant.MAX)
                .build(Purpose.SIGN);
    }

    protected SecretsProvider getSecretsProvider() throws Exception {
        SecretsProvider secretsProvider = new SecretsProvider(Clock.systemUTC());
        secretsProvider.useSpecificSecretForPurpose(Purpose.purpose(SIGNING_KEY_ID, SigningKey.class),
                getSigningKey(SIGNING_KEY_ID));
        return secretsProvider;
    }

    protected void validateSignature(SignedJWT signedJwt) {
        try {
            signedJwt.verify(rsaJwtVerifier);
        } catch (JOSEException e) {
            fail("Failed to verify signedJwt was signed by " + SIGNING_KEY_ID, e);
        }
    }

    protected void validateSignedJwt(SignedJWT signedJwt) throws ParseException {
        // Valid the header and claims match what is expected
        final JWSHeader header = signedJwt.getHeader();
        assertEquals(JWSAlgorithm.PS256, header.getAlgorithm());
        assertEquals(KID, header.getKeyID());
        final JWTClaimsSet jwtClaimsSet = signedJwt.getJWTClaimsSet();
        assertEquals("https://examplebank.com/", jwtClaimsSet.getIssuer());
        assertEquals("https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003", jwtClaimsSet.getSubject());
        assertEquals(List.of(AUD), jwtClaimsSet.getAudience());
        assertEquals(TXN, jwtClaimsSet.getClaim("txn"));
        assertEquals(JTI, jwtClaimsSet.getJWTID());
    }

    protected void validateCritClaims(JWSHeader header) {
        assertEquals(header.getCriticalParams(), critClaims.keySet());
        critClaims.forEach((k, v) -> {
            assertThat(header.getCustomParam(k)).isNotNull().isEqualTo(v);
        });
    }

    protected String aValidPayloadAsString() throws IOException {
        return new String(Json.writeJson(aValidPayloadMap()));
    }
    protected Map<String, Object> aValidPayloadMap() {
        return Map.of(
                "iss", "https://examplebank.com/",
                "iat", 1516239022,
                "jti", JTI,
                "sub", "https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003",
                "aud", AUD,
                "txn", TXN,
                "toe", 1516239022,
                "events", Map.of(
                        "urn:uk:org:openbanking:events:resource-update", Map.of(
                                "subject", Map.of(
                                        "subject_type", "http://openbanking.org.uk/rid_http://openbanking.org.uk/rty",
                                        "http://openbanking.org.uk/rid", "pmt-7290-003",
                                        "http://openbanking.org.uk/rlk", Map.of("version", "v3.0",
                                                "link", "https://examplebank.com/api/open-banking/v3.0/pisp/domestic-payments/pmt-7290-003"
                                        )
                                )
                        )
                )
        );
    }
}
