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

function payment_intent_main(){

        console.log("[DEBUG] PISP REQUEST.METHOD: " + request.method);
        switch (request.method) {

                case "create":
                        paymentIntentResult = createPaymentIntent(request.content);
			return paymentIntentResult;
                        break;

                case "read":
                        paymentIntentResult = getPaymentIntent(request.content);
                        return paymentIntentResult;
                        break;

                case "patch":
                case "action":
                        updatePaymentIntentStatusResult = updatePaymentIntent(request.content);
                        return updatePaymentIntentStatusResult;
			break;

                default:
                        throw { code : 500, message : "Invalid request" };
                        break;

        }
}

//Create initial OB Payment Intent object with status Pending
function createPaymentIntent(paymentIntentData){
	
	//Set the Payment Intent AwaitingAuthorisation status and creation date time
	paymentIntentData.Data.Status = "AwaitingAuthorisation";
	paymentIntentData.Data.CreationDateTime = generateTimestamp();
	paymentIntentData.Data.StatusUpdateDateTime = generateTimestamp();

	console.log("[DEBUG]: Input REQUEST: " + request);

	if (request.additionalParameters != null){
		var tppId = request.additionalParameters.tppId;
	}

	//Add relation to the Tpp managed object
	var returnObject = {}
    	var tppIdmId = "";
   	if (typeof tppId == 'string') {
        	tppIdmId = findTppByIdentifier(tppId);
       		if (tppIdmId != "-1"){
			paymentIntentData.Tpp = { "_ref" : CONFIG_managedObjects.obTpp + "/" + tppIdmId};
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
		
	console.log("[DEBUG] DATA paymentIntentData with status: "+ paymentIntentData);
	
	//Create the IDM OB Payment Intent object
	paymentIntentOutput = openidm.create(CONFIG_managedObjects.obDomesticPayment, "", paymentIntentData);

	var paymentUpdateIntentOutput = "";
	if (paymentIntentOutput != null){
		var updatePaymentIntent = [];
	        //Save ConsentId on the IDM Payment managed object
        	var updateConsentObject = {
                	"operation": "add",
                	"field": "/Data/ConsentId",
                	"value": paymentIntentOutput._id
	        };

		updatePaymentIntent.push(updateConsentObject);
		
	        //Update the IDM OB Payment Intent object Status
        	paymentUpdateIntentOutput = openidm.patch(CONFIG_managedObjects.obDomesticPayment + "/" + paymentIntentOutput._id, null, updatePaymentIntent);
	}
	
	if (paymentUpdateIntentOutput != null){
		paymentIntentOutput = paymentUpdateIntentOutput;
	}
	paymentIntentOutput.Links = {};
	paymentIntentOutput.Links.Self = constructIgUri(igServer) + igServer.domesticPaymentEndpoint + "/" + paymentIntentOutput._id;
	paymentIntentOutput.Meta = {};
	paymentIntentOutput.Meta.TotalPages = "1";
	delete paymentIntentOutput._id;
	delete paymentIntentOutput._rev;

	console.log("\n[DEBUG] RESULT paymentIntentOutput final: "+ paymentIntentOutput);
  
 	return paymentIntentOutput;
}


//Update OB Payment Intent status to Authorised
function updatePaymentIntent(paymentIntentData){
	
	console.log("[DEBUG] Request: "+ request);
	console.log("[DEBUG] paymentIntentData: "+ paymentIntentData);
	
	inputPaymentIntentId = request.resourcePath;
	console.log("[DEBUG] Input Payment Intent Id: "+ inputPaymentIntentId);	

	var userid = paymentIntentData.claims.sub;
	updatePaymentIntent = paymentIntentData.consent;

	for (var i=0; i < updatePaymentIntent.length; i++){
    		if ((updatePaymentIntent[i].field).equals("/Data/Status")){
	      		console.log("[DEBUG] Value of Status element: " + updatePaymentIntent[i].value);
			consentStatusUpdate = updatePaymentIntent[i].value;
			break;
		}
	}

	//Add relation to the USER managed object
        var userIdmId = "";
	var updateUserObject = "";
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
			updatePaymentIntent.push(updateUserObject);

                	var updateStatusDateTimeObject = {
                        	"operation": "replace",
                        	"field": "/Data/StatusUpdateDateTime",
                        	"value": generateTimestamp()
                	};
                	updatePaymentIntent.push(updateStatusDateTimeObject);
                }
        }

	console.log("[DEBUG] updatePaymentIntent: " + updatePaymentIntent);
	
	//Update the IDM OB Payment Intent object Status 
	paymentIntentID = openidm.patch(CONFIG_managedObjects.obDomesticPayment + "/" + inputPaymentIntentId, null, updatePaymentIntent);
	
	console.log("[DEBUG] RESULT paymentIntentID: "+ paymentIntentID);

        var qry = {
              "_queryFilter": "_id eq \"" + inputPaymentIntentId + "\"",
              "_fields" : "*,Tpp/*"
        };
        tppPaymentIntentOutput = openidm.query(CONFIG_managedObjects.obDomesticPayment, qry);
        if (tppPaymentIntentOutput != null && tppPaymentIntentOutput.result[0] != null && tppPaymentIntentOutput.result[0].Tpp != null){
                var idmTppId = tppPaymentIntentOutput.result[0].Tpp.identifier;
		var idmCertTppId = tppPaymentIntentOutput.result[0].Tpp.certId;
                console.log("[DEBUG] TPP Linked to Payment Intent for update: " + inputPaymentIntentId + " is: " + idmTppId + " having certId: " + idmCertTppId);

                if (consentStatusUpdate != null && consentStatusUpdate.equals("Authorised")){
	                //Provision Authorization Policy in AM
        	        amServer.ssoToken = AM_login_getSsoToken(amServer);
                	policyData = constructPISPPolicyData(inputPaymentIntentId, userid, paymentIntentData.claims.Initiation, idmTppId + idmCertTppId);
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

	return paymentIntentID;
}

//Get OB Payment Intent Details
function getPaymentIntent(paymentIntentData){

        var paymentIntentOutput = {};
        if (request.additionalParameters != null){
                var tppId = request.additionalParameters.tppId;
                var consentId = request.additionalParameters.consentId;
        }

	if (consentId != null && tppId != null){
                console.log("[DEBUG] Entered in getPaymentIntent() - input tppId: " + tppId + " ; consentId: " + consentId);

                var qry = {
                        "_queryFilter": "_id eq \"" + consentId + "\"",
                        "_fields" : "*,Tpp/*"
                };
                tppPaymentIntentOutput = openidm.query(CONFIG_managedObjects.obDomesticPayment, qry);
                if (tppPaymentIntentOutput != null && tppPaymentIntentOutput.result[0] != null && tppPaymentIntentOutput.result[0].Tpp != null){
                        var idmTppId = tppPaymentIntentOutput.result[0].Tpp.identifier;
			var idmCertTppId = tppPaymentIntentOutput.result[0].Tpp.certId;
                        console.log("[DEBUG] TPP Linked to Payment Intent: " + consentId + " is: " + idmTppId + " having certId: " + idmCertTppId);
                        if (idmCertTppId.equals(tppId)){
                                paymentIntentOutput = openidm.read(CONFIG_managedObjects.obDomesticPayment + "/" + consentId);
                                console.log("[DEBUG] PAYMENT INTENT OUTPUT: " + paymentIntentOutput);

                                if (paymentIntentOutput != null){
                                        paymentIntentOutput.Links = {};
                                        paymentIntentOutput.Links.Self = constructIgUri(igServer) + igServer.domesticPaymentEndpoint + "/" + paymentIntentOutput._id;
                                        paymentIntentOutput.Meta = {};
                                        paymentIntentOutput.Meta.TotalPages = "1";

                                        delete paymentIntentOutput._id;
                                        delete paymentIntentOutput._rev;
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

        return paymentIntentOutput;
}

//Construct IG URI from configuration file
function constructIgUri(igServer){
        var uri = "";

        uri = igServer.protocol + "://" + igServer.host

        return uri;
}
