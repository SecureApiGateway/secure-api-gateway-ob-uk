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
package com.forgerock.sapi.gateway.dcr.sigvalidation;

import org.forgerock.util.Reject;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;

final public class DCRSignatureValidationException extends Exception{

    private final DCRErrorCode errorCode;
    private final String errorDescription;

    public DCRSignatureValidationException(DCRErrorCode errorCode, String errorMessage) {
        this(errorCode, errorMessage, null);
    }

    public DCRSignatureValidationException(DCRErrorCode errorCode, String errorMessage, Throwable cause) {
        super((errorCode != null ? errorCode.getCode() : "") + " " + errorMessage, cause);
        this.errorCode = Reject.checkNotNull(errorCode, "errorCode must be supplied");
        this.errorDescription = Reject.checkNotBlank(errorMessage, "errorMessage must be supplied");
    }

    public DCRErrorCode getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public String toString(){
        return "error_code: '" + errorCode + "', error_description: '" + errorDescription +"'";
    }
}