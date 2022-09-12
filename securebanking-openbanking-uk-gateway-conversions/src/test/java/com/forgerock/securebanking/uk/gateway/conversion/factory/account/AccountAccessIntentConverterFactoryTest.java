package com.forgerock.securebanking.uk.gateway.conversion.factory.account;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType;
import com.forgerock.securebanking.uk.gateway.conversion.converters.account.AccountAccessIntentConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit test for {@link AccountAccessIntentConverterFactory}
 */
public class AccountAccessIntentConverterFactoryTest {
    @Test
    public void shouldReturnAccountAccessIntentConverter() {
        assertThat(AccountAccessIntentConverterFactory.getConverter(OBVersion.v3_1_8))
                .isExactlyInstanceOf(AccountAccessIntentConverter.class);
    }

    @Test
    public void couldNotFindTheConverter() {
        assertThatThrownBy(() ->
                AccountAccessIntentConverterFactory.getConverter(OBVersion.v3_1)
        ).isExactlyInstanceOf(RuntimeException.class)
                .hasMessageContaining("Couldn't find the %s converter for version %s", IntentType.ACCOUNT_ACCESS_CONSENT.name(), OBVersion.v3_1.name());
    }
}
