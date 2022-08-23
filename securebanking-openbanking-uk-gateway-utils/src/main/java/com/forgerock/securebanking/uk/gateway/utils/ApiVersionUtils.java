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
package com.forgerock.securebanking.uk.gateway.utils;

import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Util to find and provide the {@link OBVersion} from the parameter passed.
 */
public class ApiVersionUtils {
    private static final Logger logger = LoggerFactory.getLogger(ApiVersionUtils.class);
    private static final Pattern VERSION_PATTERN = Pattern.compile("v[0-9][0-9]?\\.[0-9][0-9]?\\.?[0-9]?[0-9]?");

    public static OBVersion getOBVersion(URI uri) {
        return getOBVersion(uri.getPath());
    }

    /**
     * Find and Provides the version of the API supported by this instance if it contained in the parameter passed.
     * @param s
     *         parameter passed to find the version supported.
     * @return The {@link OBVersion} matching.
     */
    public static OBVersion getOBVersion(String s) {
        Matcher matcher = VERSION_PATTERN.matcher(format(s));
        if (!matcher.find()) {
            throw new IllegalArgumentException("Unable to determine version from passed parameter: " + s);
        }
        OBVersion version = OBVersion.fromString(matcher.group());
        if (version == null) {
            logger.debug("Unknown version value from: {}", s);
            throw new IllegalArgumentException("Unknown version value from: " + s);
        }
        return version;
    }

    /**
     * Format the value to normalize it the format (vX.Y.Z)
     * @param s
     * @return param formated
     */
    private static String format(String s) {
        return s.startsWith("http") || s.startsWith("v") ? s : "v".concat(s);
    }
}
