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
package com.forgerock.securebanking.uk.gateway.conversion;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;

import java.io.IOException;

public class DateTimeDeserializerConverter extends StdDeserializer<DateTime> {

    public DateTimeDeserializerConverter() {
        this((Class) null);
    }

    public DateTimeDeserializerConverter(Class<?> vc) {
        super(vc);
    }

    @Override
    public DateTime deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        String date = jsonParser.getText();
        // parse datetime where date is mandatory and the time is optional and can parse zoned date times
        /*
        It accepts formats described by the following syntax:
          date-opt-time     = date-element ['T' [time-element] [offset]]
          date-element      = std-date-element | ord-date-element | week-date-element
          std-date-element  = yyyy ['-' MM ['-' dd]]
          ord-date-element  = yyyy ['-' DDD]
          week-date-element = xxxx '-W' ww ['-' e]
          time-element      = HH [minute-element] | [fraction]
          minute-element    = ':' mm [second-element] | [fraction]
          second-element    = ':' ss [fraction]
          fraction          = ('.' | ',') digit+
        Examples:
            - 2019-08-01T00:00:00+00:00
            - 2022-08-24T10:39:53.335Z
         */
        return DateTime.parse(date, ISODateTimeFormat.dateTimeParser());
    }
}
