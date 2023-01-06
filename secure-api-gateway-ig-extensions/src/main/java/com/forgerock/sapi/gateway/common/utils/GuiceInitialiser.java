package com.forgerock.sapi.gateway.common.utils;

import com.forgerock.sapi.gateway.dcr.request.RequestAndSsaSignatureValidationFilter;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;

public class GuiceInitialiser {

    private static GuiceInitialiser guiceInitialiser;

    public static GuiceInitialiser getGuiceInitializer(){
        if(guiceInitialiser == null){
            guiceInitialiser = new GuiceInitialiser();
        }
        return guiceInitialiser;
    }

    private GuiceInitialiser(){
        if(guiceInitialiser == null){
            guiceInitialiser = new GuiceInitialiser();
        }
    }


    static class RequestAndSsaValidationFilterModule extends AbstractModule {
        @Provides
        RequestAndSsaSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier getRegistrationRequestObjectFromJwtSupplierInstance(){
            return new RequestAndSsaSignatureValidationFilter.RegistrationRequestObjectFromJwtSupplier();
        }
    }
}
