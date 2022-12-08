package com.forgerock.sapi.gateway.oauth

import org.forgerock.util.promise.*
import org.forgerock.http.protocol.*
import com.forgerock.sapi.gateway.rest.ContentTypeNegotiator
import com.forgerock.sapi.gateway.rest.HttpMediaTypes
import org.forgerock.http.util.Json

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Factory which creates Response objects for OAuth2 releated errors as described in the following specifications:
 * https://www.rfc-editor.org/rfc/rfc6749#section-5.2
 */
class OAuthErrorResponseFactory {

    List<String> supportedMediaTypes = [ HttpMediaTypes.TEXT_HTML, HttpMediaTypes.APPLICATION_TEXT,
        HttpMediaTypes.APPLICATION_JSON, HttpMediaTypes.APPLICATION_FORM_URLENCODED, HttpMediaTypes.ALL_TYPES ]

    private final Logger logger = LoggerFactory.getLogger(getClass())
    private final ContentTypeNegotiator contentTypeNegotiator;

    private static final String INVALID_REQUEST = "invalid_request"
    private static final String INVALID_CLIENT = "invalid_client"
    private static final String INVALID_GRANT = "invalid_grant"
    private static final String UNAUTHORIZED_CLIENT = "unauthorized_client"
    private static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    private static final String INVALID_SCOPE = "invalid_scope"

    /**
     * Prefix for log messages created by this factory.
     * This is allows the x-fapi-interaction-id to be logged.
     */
    private final String logPrefix

    public OAuthErrorResponseFactory(String logPrefix) {
        this.logPrefix = logPrefix
        this.supportedMediaTypes = supportedMediaTypes
        this.contentTypeNegotiator = new ContentTypeNegotiator(logPrefix, supportedMediaTypes)
    }

    Response invalidRequestErrorResponse(Header acceptHeader, String errorDescription) {
        return createErrorResponse(INVALID_REQUEST, acceptHeader, errorDescription)
    }

    Response invalidClientErrorResponse(Header acceptHeader, String errorDescription) {
         return createErrorResponse(INVALID_CLIENT, acceptHeader, errorDescription)
     }

     Response invalidGrantErrorResponse(Header acceptHeader, String errorDescription) {
         return createErrorResponse(INVALID_GRANT, acceptHeader, errorDescription)
     }

     Response unauthorizedClientErrorResponse(Header acceptHeader, String errorDescription) {
         return createErrorResponse(UNAUTHORIZED_CLIENT, acceptHeader, errorDescription)
     }

    Response unsupportedGrantTypeErrorResponse(Header acceptHeader, String errorDescription){
        return createErrorResponse(UNSUPPORTED_GRANT_TYPE, acceptHeader, errorDescription)
    }

     Response invalidScopeErrorResponse(Header acceptHeader, String errorDescription) {
         return createErrorResponse(INVALID_SCOPE, acceptHeader, errorDescription)
     }

    Response createErrorResponse(String errorType, Header acceptHeader, String errorDescription){
        String bestContentType = contentTypeNegotiator.getBestContentType(acceptHeader)
        Form errorForm = new Form()
        errorForm.add("error", errorType)
        errorForm.add("error_description", errorDescription)
        return errorResponse(Status.BAD_REQUEST, errorForm, bestContentType)
    }

    Response errorResponse(Status httpCode, Form errorForm, String bestContentType) {
        String errorMessage = getErrorMessage(errorForm, bestContentType)
        logger.info("{} creating OAuth Error Response, http status: {}, error: {}", logPrefix, httpCode, errorMessage)
        Response response = new Response(httpCode)
        response.entity.setString(errorMessage)
        ContentTypeHeader mediaTypeHeader = new ContentTypeHeader(bestContentType, [:])
        response.addHeaders(mediaTypeHeader)
        return response
    }

    String getErrorMessage(Form errorForm, String bestContentType) {
        if(bestContentType == HttpMediaTypes.TEXT_HTML) {
            return getHtmlErrorMessage(errorForm)
        } else if (bestContentType == HttpMediaTypes.APPLICATION_FORM_URLENCODED) {
            return getFormUrlEncodedErrorMessage(errorForm)
        } else if (bestContentType == HttpMediaTypes.APPLICATION_TEXT) {
            return getTextErrorMessage(errorForm)
        } else {
            return getJsonErrorMessage(errorForm)
        }
    }

    String getHtmlErrorMessage(Form errorForm) {
        logger.debug("{}getHtmlErrorMessage, errorForm: '{}'", logPrefix,  errorForm)
        StringBuilder errorMessageBuilder = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Authorization Error" + 
          "</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body>")
        errorForm.forEach( (key, val) -> {
            logger.debug("{}processing entry for {}, val is {}", logPrefix, key, val)
            errorMessageBuilder.append("<p><b>" + key + ":</b> ")
            List<String> values = val
            Boolean first = true
            values.forEach( (innerVal) -> {
                logger.debug("{}adding value {} to error message", logPrefix, innerVal)
                if(first){
                    first = false
                } else {
                    errorMessageBuilder.append(', ')
                }
                errorMessageBuilder.append(innerVal)
            })
            errorMessageBuilder.append('</p>')
        } )
        errorMessageBuilder.append("</body></html>")
        String htmlErrorMessage =  errorMessageBuilder.toString()
        logger.debug("{}html error message is {}", logPrefix, htmlErrorMessage)
        return htmlErrorMessage
    }

    String getJsonErrorMessage(Form errorForm){
        logger.debug("{}getJsonErrorMessage, errorForm: '{}'", logPrefix, errorForm)
        String jsonErrorMessage = new String(Json.writeJson(errorForm))
        logger.debug("{}html error message is {}", logPrefix, jsonErrorMessage)
        return jsonErrorMessage
    }

    String getTextErrorMessage(Form errorForm) {
        logger.debug("{}getTextErrorMessage, errorForm: '{}'", logPrefix, errorForm)
        StringBuilder errorMessageBuilder = new StringBuilder()
        errorForm.forEach( (key, val) -> {
            logger.debug("{}processing entry for {}, val is {}", logPrefix, key, val)
            errorMessageBuilder.append(key + ": ")
            List<String> values = val
            Boolean first = true
            values.forEach( (innerVal) -> {
                logger.debug("{}adding value {} to error message", logPrefix, innerVal)
                if(!first){
                    errorMessageBuilder.append(', ')
                }
                errorMessageBuilder.append(innerVal)
                first = false
            })
            errorMessageBuilder.append('\n')
        } )
        String textErrorMessage =  errorMessageBuilder.toString()
        logger.debug("{}text error message is {}", logPrefix, textErrorMessage)
        return textErrorMessage
    }

    String getFormUrlEncodedErrorMessage(Form errorForm) {
        logger.debug("{}getFormUrlEncodedErrorMessage, errorForm: '{}'", logPrefix, errorForm)
        String formUrlEncodedErrorMessage =  errorForm.toQueryString()
        logger.debug("{}form URL encoded error message is {}", logPrefix, formUrlEncodedErrorMessage)
        return formUrlEncodedErrorMessage
    }
}