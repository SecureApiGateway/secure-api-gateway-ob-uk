import org.forgerock.http.protocol.*

next.handle(context, request).thenOnResult(response -> {
        response.entity = response.entity.getString().replace('http://rs','https://' + request.getHeaders().getFirst('Host') + '/rs');
        JsonValue accountAndTransactionApi = response.entity.getJson().get("Data").get("AccountAndTransactionAPI")
        for (JsonValue value: accountAndTransactionApi) {
                value.Links.links.add("CreateAccountAccessConsent", "https://" + request.getHeaders().getFirst('X-Forwarded-Host') +"/open-banking/" + value.Version.asString() + "/aisp/account-access-consents");
        }
        JsonValue newEntity = response.entity.getJson();
        newEntity.get("Data").remove("AccountAndTransactionAPI")
        newEntity.get("Data").add("AccountAndTransactionAPI", accountAndTransactionApi);
        response.entity = newEntity;
        return response;

        //TODO - add linkvalues as well and parameterize URLs
});