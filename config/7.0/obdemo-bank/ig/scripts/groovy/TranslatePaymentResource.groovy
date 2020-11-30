request.uri.path = request.uri.path.replace("/openbanking/v3.1","")
next.handle(context, request)
