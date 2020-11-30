next.handle(context, request).thenOnResult(response -> {

  def rspJson = response.entity.getJson();


  rspJson.registration_endpoint = rspJson.registration_endpoint.replace(internalUri,externalUri)
  rspJson.token_endpoint        = rspJson.token_endpoint.replace(internalUri,externalUri)


  response.setEntity(rspJson)

  return response;
})
