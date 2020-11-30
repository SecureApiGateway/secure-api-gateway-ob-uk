/***************************************************************************
 *  Copyright 2019 ForgeRock AS.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ***************************************************************************/
load("script/obie/config.js");
load("script/obie/ob_utils.js");
load("script/obie/fr_am_utils.js");
load("script/obie/ob_am_policy.js");
load("script/obie/ob_tpp.js");
 
function account_access_intent_main(){
	
	console.log("[DEBUG] AISP REQUEST.METHOD: " + request.method);
	switch (request.method) {

                case "create":
                	accountIntentResult = createAccountIntent(request.content);
 	                return accountIntentResult;
			break;

                case "read":
                        accountIntentResult = getAccountIntent(request.content);
                        return accountIntentResult;
                        break;

                case "patch":
		case "action":
                        updateAccountIntentStatusResult = updateAccountIntent(request.content);
                        return updateAccountIntentStatusResult;
			break;

		case "delete":
                        deleteIntentResult = deleteAccountIntent(request.content);
                        return deleteIntentResult;
	
                default:
                        throw { code : 500, message : "Invalid request" };
                	break;

        }
}

function createAccountIntent(accountIntentData){

        //Set the Payment Intent AwaitingAuthorisation status and creation date time
        accountIntentData.Data.Status = "AwaitingAuthorisation";
        accountIntentData.Data.CreationDateTime = generateTimestamp();
        accountIntentData.Data.StatusUpdateDateTime = generateTimestamp();

       if (request.additionalParameters != null){
                var tppId = request.additionalParameters.tppId;
        }

        //Add relation to the Tpp managed object
        var returnObject = {}
        var newObject = {}
        var tppIdmId = "";
        if (typeof tppId == 'string') {
                tppIdmId = findTppByIdentifier(tppId);
                if (tppIdmId != "-1"){
                        accountIntentData.Tpp = { "_ref" : CONFIG_managedObjects.obTpp + "/" + tppIdmId};
                }
		/*
                else {
                        returnObject.reason = "Invalid tppIdentifier";
                        return returnObject;
                }
		*/
        }
        else{
                returnObject.reason = "tppIdentifier must be specified as a string";
        }

        console.log("[DEBUG] DATA accountIntentData with status: "+ accountIntentData);

        //Create the IDM OB Payment Intent object
        accountAccessOutput = openidm.create(CONFIG_managedObjects.obAccountAccess, "", accountIntentData);

	var accountUpdateIntentOutput = "";
        if (accountAccessOutput != null){
                var updateAccountIntent = [];
                //Save ConsentId on the IDM Account Access managed object
                var updateConsentObject = {
                        "operation": "add",
                        "field": "/Data/ConsentId",
                        "value": accountAccessOutput._id
                };

                updateAccountIntent.push(updateConsentObject);

                //Update the IDM OB Payment Intent object Status
                accountUpdateIntentOutput = openidm.patch(CONFIG_managedObjects.obAccountAccess + "/" + accountAccessOutput._id, null, updateAccountIntent);
        }

        if (accountUpdateIntentOutput != null){
                accountAccessOutput = accountUpdateIntentOutput;
        }

        accountAccessOutput.Links = {};
        accountAccessOutput.Links.Self = constructIgUri(igServer) + igServer.accountAccessEndpoint + "/" + accountAccessOutput._id;
        accountAccessOutput.Meta = {};
	accountAccessOutput.Meta.TotalPages = "1";

        delete accountAccessOutput._id;
        delete accountAccessOutput._rev;

        console.log("\n[DEBUG] RESULT accountAccessOutput final: "+ accountAccessOutput);
   
	return accountAccessOutput;
}


//Update OB Account Information Intent status to Authorised
function updateAccountIntent(accountIntentData){
	
	console.log("[DEBUG] Request: "+ request);
	console.log("[DEBUG] accountIntentData: "+ accountIntentData);
	
	inputAccountIntentId = request.resourcePath;
	console.log("[DEBUG] Input Account Information Intent Id: "+ inputAccountIntentId);	

        var userid = accountIntentData.claims.sub;
        updateAccountAccessIntent = accountIntentData.consent;

        for (var i=0; i < updateAccountAccessIntent.length; i++){
                if ((updateAccountAccessIntent[i].field).equals("/Data/Status")){
                        console.log("[DEBUG] Value of Status element: " + updateAccountAccessIntent[i].value);
                        consentStatusUpdate = updateAccountAccessIntent[i].value;
                        break;
                }
        }

        //Add relation to the USER managed object
        var userIdmId = "";
        if (typeof userid == 'string') {
                userIdmId = findUser(userid);
                console.log("[DEBUG] User: " + userid + " has the IDM ID: " + userIdmId);
                if (userIdmId != "-1"){
                        updateUserObject = {
                                "operation":"add",
                                "field":"User",
                                "value":{
                                        "_ref": "managed/user/" + userIdmId,
                                }
                        };
                        updateAccountAccessIntent.push(updateUserObject);

                        var updateStatusDateTimeObject = {
                                "operation": "replace",
                                "field": "/Data/StatusUpdateDateTime",
                                "value": generateTimestamp()
                        };
                        updateAccountAccessIntent.push(updateStatusDateTimeObject);
                }
        }
        console.log("[DEBUG] updateAccountAccessIntent: " + updateAccountAccessIntent);

	
	//Update the IDM OB Account Access Intent object Status 
	accountIntentID = openidm.patch(CONFIG_managedObjects.obAccountAccess + "/" + inputAccountIntentId, null, updateAccountAccessIntent);
	
	console.log("[DEBUG] RESULT accountIntentID: "+ accountIntentID);

	var qry = {
	      "_queryFilter": "_id eq \"" + inputAccountIntentId + "\"",
              "_fields" : "*,Tpp/*"
        };
        tppAccountIntentOutput = openidm.query(CONFIG_managedObjects.obAccountAccess, qry);
        if (tppAccountIntentOutput != null && tppAccountIntentOutput.result[0] != null && tppAccountIntentOutput.result[0].Tpp != null){
        	var idmTppId = tppAccountIntentOutput.result[0].Tpp.identifier;
		var idmCertTppId = tppAccountIntentOutput.result[0].Tpp.certId;
                console.log("[DEBUG] TPP Linked to Intent for update: " + inputAccountIntentId + " is: " + idmTppId + " having certId: " + idmCertTppId);	

	        if (consentStatusUpdate != null && consentStatusUpdate.equals("Authorised")){
			//Provision Authorization Policy in AM
			amServer.ssoToken = AM_login_getSsoToken(amServer);
			policyData = constructAISPPolicyData(inputAccountIntentId, userid, accountIntentData.claims.accounts, idmTppId + idmCertTppId);
			AM_policy_create(amServer, policyData);
			AM_logout(amServer);
		}
		else {
        	        console.log("[DEBUG] No AM Policy was created due to the Consent Status: " + consentStatusUpdate);
			throw { code : 400, message : "Bad Request" };
        	}
	}
	else {
		throw { code : 400, message : "Bad Request" };
	}
  
    return accountIntentID;
}

//Get OB Account Information Intent Details
function getAccountIntent(accountIntentData){
	
	var accountIntentOutput = {};
	if (request.additionalParameters != null){
                var tppId = request.additionalParameters.tppId;
		var consentId = request.additionalParameters.consentId;
        }

	if (consentId != null && tppId != null){
		console.log("[DEBUG] Entered in getAccountIntent() - input tppId: " + tppId + " ; consentId: " + consentId);

		var qry = {
			"_queryFilter": "_id eq \"" + consentId + "\"",
  			"_fields" : "*,Tpp/*"
		};
		tppAccountIntentOutput = openidm.query(CONFIG_managedObjects.obAccountAccess, qry);
		if (tppAccountIntentOutput != null && tppAccountIntentOutput.result[0] != null && tppAccountIntentOutput.result[0].Tpp != null){
			var idmTppId = tppAccountIntentOutput.result[0].Tpp.identifier;
                        var idmTppCertId = tppAccountIntentOutput.result[0].Tpp.certId;
                        console.log("[DEBUG] TPP Linked to Intent: " + consentId + " is: " + idmTppId + " having certId: " + idmTppCertId);
                        if (idmTppCertId.equals(tppId)){
				accountIntentOutput = openidm.read(CONFIG_managedObjects.obAccountAccess + "/" + consentId);
				console.log("[DEBUG] ACCOUNT INTENT OUTPUT: " + accountIntentOutput);

				if (accountIntentOutput != null){
				        accountIntentOutput.Links = {};
        				accountIntentOutput.Links.Self = constructIgUri(igServer) + igServer.accountAccessEndpoint + "/" + accountIntentOutput._id;
        				accountIntentOutput.Meta = {};
	        			accountIntentOutput.Meta.TotalPages = "1";

					delete accountIntentOutput._id;
					delete accountIntentOutput._rev;	
				}
			}
			else {
				throw { code : 403, message : "Forbidden" };
			}
		}
		else {
	                throw { code : 404, message : "Not Found" };
                }

	}

	return accountIntentOutput;
}

//Delete OB Account Information Intent
function deleteAccountIntent(accountIntentData){

        var accountIntentOutput = {};
        if (request.additionalParameters != null){
                var tppId = request.additionalParameters.tppId;
                var consentId = request.additionalParameters.consentId;
        }

	if (consentId != null && tppId != null){
                console.log("[DEBUG] Entered in deleteAccountIntent() - input tppId: " + tppId + " ; consentId: " + consentId);

                var qry = {
                        "_queryFilter": "_id eq \"" + consentId + "\"",
                        "_fields" : "*,Tpp/*"
                };
                tppAccountIntentOutput = openidm.query(CONFIG_managedObjects.obAccountAccess, qry);
                if (tppAccountIntentOutput != null && tppAccountIntentOutput.result[0] != null && tppAccountIntentOutput.result[0].Tpp != null){
                        var idmTppId = tppAccountIntentOutput.result[0].Tpp.identifier;
                        var idmTppCertId = tppAccountIntentOutput.result[0].Tpp.certId;
			console.log("[DEBUG] TPP Linked to Intent: " + consentId + " is: " + idmTppId + " having certId: " + idmTppCertId);
                        if (idmTppCertId.equals(tppId)){
                                accountIntentOutput = openidm.delete(CONFIG_managedObjects.obAccountAccess + "/" + consentId, null);

                		//Delete Authorization Policy in AM
       	         		amServer.ssoToken = AM_login_getSsoToken(amServer);
        	     		AM_policy_delete(amServer, "aisp-" + consentId);
                		AM_logout(amServer);
                		console.log("[DEBUG] Policy aisp-" + consentId + " was deleted from AM.");
                       	}
                        else {
                                throw { code : 403, message : "Forbidden" };
                        }
                }
                else {
                        throw { code : 403, message : "Forbidden" };
                }

        }
        else {
                console.log("[DEBUG] No IDM Object and  AM Policy were deleted");
		throw { "code": 400, "message": "", "detail": "" };
        }

	throw { "code": 204, "message": "", "detail": "" };
}


function constructIgUri(igServer){
        var uri = "";

        uri = igServer.protocol + "://" + igServer.host

        return uri;
}
