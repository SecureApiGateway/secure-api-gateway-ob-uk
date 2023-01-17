/*
 * Copyright © 2020-2022 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.dcr.request;

import org.forgerock.util.Reject;

final public class DCRSignatureValidationException extends Exception{

    public enum ErrorCode {
        INVALID_REDIRECT_URI("invalid_redirect_uri"),
        INVALID_CLIENT_METADATA("invalid_client_metadata"),
        INVALID_SOFTWARE_STATEMENT("invalid_software_statement"),
        UNAPPROVED_SOFTWARE_STATEMENT("unapproved_software_statement");

        private final String code;

        ErrorCode(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }
    }

    private final ErrorCode errorCode;
    private final String errorDescription;

    public DCRSignatureValidationException(ErrorCode errorCode, String errorMessage) {
        this(errorCode, errorMessage, null);
    }

    public DCRSignatureValidationException(ErrorCode errorCode, String errorMessage, Throwable cause) {
        super((errorCode != null ? errorCode.code : "") + " " + errorMessage, cause);
        this.errorCode = Reject.checkNotNull(errorCode, "errorCode must be supplied");
        this.errorDescription = Reject.checkNotBlank(errorMessage, "errorMessage must be supplied");
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public String toString(){
        return "error_code: '" + errorCode + "', error_description: '" + errorDescription +"'";
    }
}