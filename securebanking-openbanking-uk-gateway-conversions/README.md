## Conversions module

This business logic contains the implementation to support the conversions from IDM intent objects to OB data model
consent response objects.
Used by `conversion-filter` module.

### Components

- A Generic intent converter pattern
- All intent converters for each intent (consent)
- A Generic converter mapper to deserialize and serialize the objects
- A factory to instance the proper converter depending on the intent type passed

## Pom use

```xml

<dependency>
    <groupId>com.forgerock.securebanking.uk.gateway</groupId>
    <artifactId>securebanking-openbanking-uk-gateway-conversions</artifactId>
    <version>${project.parent.version}</version>
</dependency>
```
