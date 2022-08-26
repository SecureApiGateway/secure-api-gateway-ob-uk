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
package com.forgerock.securebanking.uk.gateway.conversion.converters;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;

import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Generic converter to provide a common way conversion between json string and OB object types
 * @param <T> represents OB data model object
 */
public class GenericIntentConverter<T> {
    private final Function<String, T> fromJsonString;
    private final ObjectMapper mapper;

    public GenericIntentConverter(final Function<String, T> fromJsonString, ObjectMapper mapper) {
        this.fromJsonString = fromJsonString;
        this.mapper = mapper;
    }

    public GenericIntentConverter(final Function<String, T> fromJsonString) {
        this.fromJsonString = fromJsonString;
        this.mapper = customizedMapper();
    }

    public final T convertFromJsonString(final String jsonString) {
        return (T) fromJsonString.apply(jsonString);
    }

    public final List<T> createFromJsonStrings(final Collection<String> jsonStrings) {
        return jsonStrings.stream().map(this::convertFromJsonString).collect(Collectors.toList());
    }

    public static ObjectMapper customizedMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JodaModule());
        mapper.enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
        mapper.enable(MapperFeature.USE_BASE_TYPE_AS_DEFAULT_IMPL);
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        //TODO Is it necessary deserialize the date time to specific ISO 8601 date format?
        /*
        SimpleModule customModule = new SimpleModule();
        customModule.addDeserializer(DateTime.class, new DateTimeDeserializerConverter());
        mapper.registerModule(customModule);
         */
        return mapper;
    }
}
