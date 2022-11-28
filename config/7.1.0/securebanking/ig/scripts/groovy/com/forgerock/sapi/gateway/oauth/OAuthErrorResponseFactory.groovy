package com.forgerock.sapi.gateway.oauth

import org.forgerock.util.promise.*
import org.forgerock.http.protocol.*
import com.forgerock.sapi.gateway.rest.ContentTypeNegotiator
import com.forgerock.sapi.gateway.rest.HttpMediaTypes
import org.forgerock.http.util.Json

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Factory which creates Response objects for error states when validating a DCR (Dynamic Client Registration) request
 */
class OAuthErrorResponseFactory {

    List<String> supportedMediaTypes = [ HttpMediaTypes.TEXT_HTML, HttpMediaTypes.APPLICATION_TEXT,
        HttpMediaTypes.APPLICATION_JSON, HttpMediaTypes.APPLICATION_FORM_URLENCODED, HttpMediaTypes.ALL_TYPES ]

    private final Logger logger = LoggerFactory.getLogger(getClass())
    private final ContentTypeNegotiator contentTypeNegotiator;

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

    Response invalidRequestErrorResponse(Header acceptHeader, Form errorForm) {
        String bestContentType = contentTypeNegotiator.getBestContentType(acceptHeader)
        errorForm.add("error", "invalid_request")
        return errorResponse(Status.BAD_REQUEST, errorForm, bestContentType)
    }

     Response invalidClientErrorResponse(Header acceptHeader, Form errorForm) {
         String bestContentType = contentTypeNegotiator.getBestContentType(acceptHeader)
         errorForm.add("error", "invalid_client")
         return errorResponse(Status.BAD_REQUEST, errorForm, bestContentType)
     }

     Response invalidGrantErrorResponse(Header acceptHeader, Form errorForm) {
         String bestContentType = contentTypeNegotiator.getBestContentType(acceptHeader)
         errorForm.add("error", "invalid_grant")
         return errorResponse(Status.BAD_REQUEST, errorForm, bestContentType)
     }

     Response unsupportedGrantTypeErrorResponse(Header acceptHeader, Form errorForm) {
         String bestContentType = contentTypeNegotiator.getBestContentType(acceptHeader)
         errorForm.add("error", "invalid_grant")
         return errorResponse(Status.BAD_REQUEST, errorForm, bestContentType)
     }

     Response unauthorizedClientErrorResponse(Header acceptHeader, Form errorForm) {
         String bestContentType = contentTypeNegotiator.getBestContentType(acceptHeader)
         errorForm.add("error", "unauthorized_client")
         return errorResponse(Status.BAD_REQUEST, errorForm, bestContentType)
     }

     Response invalidScopeErrorResponse(Header acceptHeader, Form errorForm) {
         String bestContentType = contentTypeNegotiator.getBestContentType(acceptHeader)
         errorForm.add("error", "invalid_scope")
         return errorResponse(Status.BAD_REQUEST, errorForm, bestContentType)
     }

    Response errorResponse(Status httpCode, Form errorForm, String bestContentType) {
        String errorMessage = getErrorMessage(errorForm, bestContentType)
        logger.warn("{} creating OAuth Error Response, http status: {}, error: {}", logPrefix, httpCode, errorMessage)
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
            errorMessageBuilder.append("<p>" + key + ": ")
            List<String> values = val
            Boolean first = true
            values.forEach( (innerVal) -> {
                logger.debug("{}adding value {} to error message", logPrefix, innerVal)
                if(!first){
                    errorMessageBuilder.append(', ')
                    first = false
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
                    first = false
                }
                errorMessageBuilder.append(innerVal)
            })
            errorMessageBuilder.append('\n')
        } )
        String textErrorMessage =  errorMessageBuilder.toString()
        logger.debug("{}text error message is {}", logPrefix, textErrorMessage)
        return textErrorMessage
    }

    String getFormUrlEncodedErrorMessage(Form errorForm) {
        logger.debug("{}getFormUrlEncodedErrorMessage, errorForm: '{}'", logPrefix, errorForm)
        StringBuilder errorMessageBuilder = new StringBuilder()
        errorForm.forEach( (key, val) -> {
            logger.debug("{}processing entry for {}, val is {}", logPrefix, key, val)
            errorMessageBuilder.append(key + "=")
            List<String> values = val
            Boolean first = true
            values.forEach( (innerVal) -> {
                logger.debug("{}adding value {} to error message", logPrefix, innerVal)
                if(!first){
                    errorMessageBuilder.append(',')
                    first = false
                }
                errorMessageBuilder.append(innerVal)
            })
            errorMessageBuilder.append('&')
        } )
        String formUrlEncodedErrorMessage =  URLEncoder.encode(errorMessageBuilder.toString(), 'UTF-8')
        logger.debug("{}form URL encoded error message is {}", logPrefix, formUrlEncodedErrorMessage)
        return formUrlEncodedErrorMessage
    }
}