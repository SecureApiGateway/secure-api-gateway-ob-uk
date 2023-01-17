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
package com.forgerock.sapi.gateway.dcr.utils;

import javax.validation.constraints.NotNull;

import org.apache.ivy.util.StringUtils;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.exceptions.JwtReconstructionException;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;

import com.forgerock.sapi.gateway.dcr.request.DCRSignatureValidationException;
import com.forgerock.sapi.gateway.dcr.request.DCRSignatureValidationException.ErrorCode;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

/**
 * A utility class providing methods used by the dcr.request classes
 */
public class DCRUtils {

    /**
     * get the value 'iss' claim, which hold a value indicating the issuer of the JWT.
     * @param jwtName the name of the jwt from which the issuer is being obtained. Used in the error_description
     *                of the exception thrown if the issuer can't be obtained
     * @param signedJwt the signed JWT from which to obtain the issuer
     * @return a string containing the issuer
     * @throws DCRSignatureValidationException if the JWT does not contain an issuer claim
     */
    @NotNull
    public String getJwtIssuer(String jwtName, SignedJwt signedJwt) throws DCRSignatureValidationException {
        String ssaIssuer = signedJwt.getClaimsSet().getIssuer();
        if (StringUtils.isNullOrEmpty(ssaIssuer)) {
            String errorDescription = "JWT '" + jwtName + "' must contain an issuer claim";
            throw new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }
        return ssaIssuer;
    }

    /**
     * get the value 'iss' claim, which hold a value indicating the issuer of the JWT.
     * @param jwtName the name of the jwt from which the issuer is being obtained. Used in the error_description
     *                of the exception thrown if the issuer can't be obtained
     * @param jwtClaimsset the jwt claims set from which to obtain the issuer
     * @return a string containing the issuer
     * @throws DCRSignatureValidationException if the JWT does not contain an issuer claim
     */
    @NotNull
    public String getJwtIssuer(String jwtName, JwtClaimsSet jwtClaimsset) throws DCRSignatureValidationException {
        String ssaIssuer = jwtClaimsset.getIssuer();
        if (StringUtils.isNullOrEmpty(ssaIssuer)) {
            String errorDescription = "JWT '" + jwtName + "' must contain an issuer claim";
            throw new DCRSignatureValidationException(ErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription);
        }
        return ssaIssuer;
    }


    /**
     * Return the Trusted Directory for the issuer. If no trusted directory exists for that issuer, throw a DCR
     * exception
     * @param trustedDirectoryService used to obtain the trusted directory associated with a jwt
     * @param ssaIssuer the issuer of the jwt used to look up the {@code TrustedDirectory} config
     * @return a {@code TrustedDirectory}
     * @throws DCRSignatureValidationException if no {@code TrustedDirectory} exists for the ssaIssuer provided
     */
    @NotNull
    public TrustedDirectory getIssuingDirectory(TrustedDirectoryService trustedDirectoryService, String ssaIssuer)
            throws DCRSignatureValidationException {
        TrustedDirectory ssaIssuingDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(ssaIssuer);
        if(ssaIssuingDirectory == null){
            throw new DCRSignatureValidationException(ErrorCode.UNAPPROVED_SOFTWARE_STATEMENT, "The issuer of the " +
                    "software statement " + ssaIssuer + " is not trusted by this DCR system");
        }
        return ssaIssuingDirectory;
    }

    /**
     * Reconstruct a signed jwt from a b64 encoded jwt string
     * @param b64EncodedJwtString the string from which the JWT is to be constructed
     * @return a {@code SignedJwt}
     * @throws com.forgerock.sapi.gateway.dcr.utils.JwtReconstructionException when the jwt can't be reconstructed from
     * the b64EncodedJwtString
     */
    @NotNull
    public SignedJwt getSignedJwt(String b64EncodedJwtString)
            throws com.forgerock.sapi.gateway.dcr.utils.JwtReconstructionException {
        try {
            return new JwtReconstruction().reconstructJwt(b64EncodedJwtString, SignedJwt.class);
        } catch ( JwtReconstructionException e){
            throw new com.forgerock.sapi.gateway.dcr.utils.JwtReconstructionException("Failed to reconstruct jwt from "
                    + "b64 encoded jwt string '" + b64EncodedJwtString + "'", e);
        }
    }
}
