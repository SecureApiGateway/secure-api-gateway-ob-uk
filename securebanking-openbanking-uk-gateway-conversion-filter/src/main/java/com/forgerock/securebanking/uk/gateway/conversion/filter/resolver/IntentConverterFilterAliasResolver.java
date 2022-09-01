package com.forgerock.securebanking.uk.gateway.conversion.filter.resolver;

import com.forgerock.securebanking.uk.gateway.conversion.filter.IntentConverterFilter;
import org.forgerock.openig.alias.ClassAliasResolver;

import java.util.HashMap;
import java.util.Map;

/**
 * Allow use of short name aliases in configuration object types. <br/>
 * Alias for {@link IntentConverterFilter}.<br/>
 * This allows a configuration with {@code "type": "IntentConverterFilter"}
 * instead of {@code "type": "com.forgerock.securebanking.uk.gateway.conversion.filter.IntentConverterFilter"}.
 */
public class IntentConverterFilterAliasResolver implements ClassAliasResolver {

    private static final Map<String, Class<?>> ALIASES =
            new HashMap<>();

    static {
        ALIASES.put("IntentConverterFilter", IntentConverterFilter.class);
    }

    /**
     * Get the class for a short name alias.
     *
     * @param alias Short name alias.
     * @return      The class, or null if the alias is not defined.
     */
    @Override
    public Class<?> resolve(final String alias) {
        return ALIASES.get(alias);
    }
}
