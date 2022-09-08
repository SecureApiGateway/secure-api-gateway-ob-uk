package com.forgerock.securebanking.uk.gateway.utils;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link ApiVersionUtils }
 */
public class ApiVersionUtilsTest {

    private final String PATH = "/rs/open-banking/v3.1.8/aisp/account-access-consents";

    @Test
    public void shouldGetOBVersionFromUri() {
        URI uri = URI.create(PATH);
        assertThat(ApiVersionUtils.getOBVersion(uri)).isEqualTo(OBVersion.v3_1_8);
    }

    @Test
    public void shouldGetOBVersionFromString() {
        assertThat(ApiVersionUtils.getOBVersion(PATH)).isEqualTo(OBVersion.v3_1_8);
    }

    @Test
    public void shouldRaiseDetermineVersionError() {
        String path = "/path/path/path";
        assertThatThrownBy(() ->
                ApiVersionUtils.getOBVersion(path)
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unable to determine version from passed parameter: " + path);
    }

    @Test
    public void shouldRaiseUnknownVersionError() {
        String path = "/path/v9.9.9/path";
        assertThatThrownBy(() ->
                ApiVersionUtils.getOBVersion(path)
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown version value from: " + path);
    }
}
