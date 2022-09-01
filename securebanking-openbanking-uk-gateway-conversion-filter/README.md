## Conversion Filter module
This filter module implements the below components:
- A filter to convert IDM object represented as json payload intent to OB data model consent response objects.
- A Class alias resolver to allow the use of short name `IntentConverterFilter` instead of fully qualified class name.
## Configuration
The filter must have received:
- `intentType`: An **IntentType** in string format as required field
- `payloadFrom`: A **MessageType** in string format to get the intent payload as required field
- `restulTo`: A list of **MessageType** in string format to set the conversion result as optional, the default value is `"RESPONSE"`,
it means that the result object of the conversion will be set in the response.
### Intent types supported values
The `intentType` field indicates the intent type to be converted
> @See com.forgerock.securebanking.openbanking.uk.common.api.meta.share.IntentType

> Required

| IntentType                                    | Value                                           |
|-----------------------------------------------|-------------------------------------------------|
| ACCOUNT_ACCESS_CONSENT                        | "ACCOUNT_ACCESS_CONSENT"                        |
| PAYMENT_DOMESTIC_CONSENT                      | "PAYMENT_DOMESTIC_CONSENT"                      |
| PAYMENT_DOMESTIC_SCHEDULED_CONSENT            | "PAYMENT_DOMESTIC_SCHEDULED_CONSENT"            |
| PAYMENT_DOMESTIC_STANDING_ORDERS_CONSENT      | "PAYMENT_DOMESTIC_STANDING_ORDERS_CONSENT"      |
| PAYMENT_INTERNATIONAL_CONSENT                 | "PAYMENT_INTERNATIONAL_CONSENT"                 |
| PAYMENT_INTERNATIONAL_SCHEDULED_CONSENT       | "PAYMENT_INTERNATIONAL_SCHEDULED_CONSENT"       |
| PAYMENT_INTERNATIONAL_STANDING_ORDERS_CONSENT | "PAYMENT_INTERNATIONAL_STANDING_ORDERS_CONSENT" |
| PAYMENT_FILE_CONSENT                          | "PAYMENT_FILE_CONSENT"                          |
| FUNDS_CONFIRMATION_CONSENT                    | "FUNDS_CONFIRMATION_CONSENT"                    |

### Payload from
The `payloadFrom` field indicates where the filter needs to get the payload to be converted.
>@See org.forgerock.openig.util.MessageType

> Required

| Value      | type   | Description                                       |
|------------|--------|---------------------------------------------------|
| "REQUEST"  | String | The filter will get the payload from the request  |
| "RESPONSE" | String | The filter will get the payload from the response |

### result to
The `resultTo` field is `optional` and indicates where the filter will set the result OB Object of the conversion
>@See org.forgerock.openig.util.MessageType

> Optional: default value ["RESPONSE"]

| Value                   | type           | Description                                                                        |
|-------------------------|----------------|------------------------------------------------------------------------------------|
| ["REQUEST"]             | List of String | The result Object of the conversion will be set in the request                     |
| ["RESPONSE"] *Default   | List of String | The result Object of the conversion will be set in the response                    |
| ["REQUEST", "RESPONSE"] | List of String | The result Object of the conversion will be set in the request and in the response |

### Filter configuration examples
```json
{
  "name": "IntentConverterFilter-AccountAccessConsent",
  "type": "IntentConverterFilter",
  "config": {
    "intentType": "ACCOUNT_ACCESS_CONSENT",
    "payloadFrom": "REQUEST"
  }
}
```
```json
{
  "name": "IntentConverterFilter-AccountAccessConsent",
  "type": "IntentConverterFilter",
  "config": {
    "intentType": "ACCOUNT_ACCESS_CONSENT",
    "payloadFrom": "RESPONSE",
    "resultTo": ["REQUEST"]
  }
}
```
```json
{
  "name": "IntentConverterFilter-AccountAccessConsent",
  "type": "IntentConverterFilter",
  "config": {
    "intentType": "ACCOUNT_ACCESS_CONSENT",
    "payloadFrom": "REQUEST",
    "resultTo": [
      "RESPONSE",
      "REQUEST"
    ]
  }
}
```
