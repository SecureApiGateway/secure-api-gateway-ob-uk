import java.util.Base64

def cnfKey = "{ \"x5t#S256\" : \"" + attributes._ig_client_certificate_thumbprint__ + "\" }"

def cnfKeyb64 = Base64.getEncoder().encodeToString(cnfKey.getBytes())

request.setEntity(request.entity.getString() + '&cnf_key=' + cnfKeyb64)

next.handle(context, request)
