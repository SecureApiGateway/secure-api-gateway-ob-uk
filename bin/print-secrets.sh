#!/bin/bash

getsec () {
    kubectl get secret $1 -o jsonpath="{.data.$2}" | base64 --decode
}

amadmin_password () {
    echo "$(getsec am-env-secrets AM_PASSWORDS_AMADMIN_CLEAR) (amadmin user)"
}

profile_passwords () {
    echo ""
}

openidm_admin_password () {
    echo "$(getsec idm-env-secrets OPENIDM_ADMIN_PASSWORD) (openidm-admin user)"
}

7.2.0_directory_manager_password () {
    echo "$(getsec ds-passwords dirmanager\\.pw) (uid=admin user)"
}

7.2.0_setup_profile_service_account_passwords () {
    [ $1 == "cfg" ] || [ $1 == "all" ] && echo "$(getsec ds-env-secrets AM_STORES_APPLICATION_PASSWORD
) (Application store service account (uid=am-config,ou=admins,ou=am-config))"
    [ $1 == "cts" ] || [ $1 == "all" ] && echo "$(getsec ds-env-secrets AM_STORES_CTS_PASSWORD) (CTS profile service account (uid=openam_cts,ou=admins,ou=famrecords,ou=openam-session,ou=tokens))"
    [ $1 == "usr" ] || [ $1 == "all" ] && echo "$(getsec ds-env-secrets AM_STORES_USER_PASSWORD) (Identity repository service account (uid=am-identity-bind-account,ou=admins,ou=identities))"
}

backup_restore_info () {
    echo ""
    echo "To back up all the generated secrets:"
    echo ""
    echo "  kubectl get secret -lsecrettype=forgeops-generated -o yaml > secrets.yaml"
    echo ""
    echo "To restore the backed up secrets:"
    echo ""
    echo "  kubectl apply -f secrets.yaml"
    echo ""
}

# Get major version by presence of a version specific secret.
get_version () {
    if ( secret=$(kubectl get secret ds-env-secrets 2>/dev/null) ); then
        version="7.2.0"
    else
        echo "Can't find any secrets"
        exit 1
    fi
}

get_version

# Either get individual passwords or display all passwords if no args provided.
if [[ "$#" > 0 ]]; then
    # Individual passwords
    case $1 in 
            "amadmin")
                amadmin_password | head -n 1 | awk '{print $1;}'
            ;;

            "idmadmin")
                [[ "$version" == "7.2.0" ]] && echo "openidm-admin" && exit 0
            ;;

            "dsadmin")
                ${version}_directory_manager_password | head -n 1 | awk '{print $1;}'
            ;;

            "dscfg")
                ${version}_setup_profile_service_account_passwords cfg | head -n 1 | awk '{print $1;}'
            ;;

            "dscts")
                ${version}_setup_profile_service_account_passwords cts | head -n 1 | awk '{print $1;}'
            ;;

            "dsusr")
                ${version}_setup_profile_service_account_passwords usr | head -n 1 | awk '{print $1;}'
            ;;

            *)
                printf "\nNOTE: Incorrect argument. Please provide the following arguments: \n"
                echo "./printSecrets.sh amadmin  - amadmin user"
                echo "./printSecrets.sh dsadmin  - uid=admin user"
                echo "./printSecrets.sh dscfg    - Config store service account (uid=am-config,ou=admins,ou=am-config)"
                echo "./printSecrets.sh dscts    - CTS profile service account (uid=openam_cts,ou=admins,ou=famrecords,ou=openam-session,ou=tokens)"
                echo "./printSecrets.sh dsusr    - Identity repository service account (uid=am-identity-bind-account,ou=admins,ou=identities)"
                exit 1;
            ;;
    esac
else
    echo ""  
    echo "Administrator passwords:"
    echo ""  
    amadmin_password
    ${version}_directory_manager_password
    echo ""
    echo "Passwords for service accounts generated by setup profiles:"
    echo ""
    ${version}_setup_profile_service_account_passwords all
    backup_restore_info
fi
