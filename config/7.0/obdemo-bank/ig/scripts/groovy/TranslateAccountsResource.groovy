// TODO: get accounts from arg

accounts = contexts.jwtBuilder.value

request.uri.path = request.uri.path.replace("/openbanking/v3.1","")

if (request.uri.path.endsWith("/accounts")) {
  request.uri.path += "/"
}
request.uri.query = "accounts=" + accounts

next.handle(context, request)
