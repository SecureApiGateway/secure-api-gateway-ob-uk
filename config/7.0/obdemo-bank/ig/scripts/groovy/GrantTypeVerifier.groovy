SCRIPT_NAME = "[GrantTypeVerifier] - "
logger.debug(SCRIPT_NAME + "Running...")

logger.debug(SCRIPT_NAME + "Access token info: " + contexts.oauth2.accessToken.info)
logger.debug(SCRIPT_NAME + "Access token info: " + contexts.oauth2.accessToken.info.grant_type)
next.handle(context,request)
