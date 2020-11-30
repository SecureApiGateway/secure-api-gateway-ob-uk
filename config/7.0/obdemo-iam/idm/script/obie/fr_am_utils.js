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

function constructAmUri(amServer){
	var uri = "";
	
	uri = amServer.protocol + "://" + amServer.host + "/" + amServer.path
	
	return uri;
}

function AM_logout(amServer){
	var result = {};
	var ssoToken = amServer.ssoToken;
	
	restCall = {};
	restCall.url = constructAmUri(amServer) + "/json/sessions/?_action=logout";
	restCall.headers = { "contentType" 	   : "application/json", 
			     "Accept-API-Version"  : "resource=2.0, protocol=1.0",
			     "iPlanetDirectoryPro" : ssoToken};
	restCall.body = "{}";
	restCall.method = "POST";
	
	result = executeRest(restCall);
	
	if (result.result == "Successfully logged out"){
		amServer.loggedin = false;
		amServer.ssoToken = "";
		return "SUCCESS";	

	}
	else{
		return "FAILED";
	}
	
}

function AM_login_getSsoToken(amServer){
	var ssoToken = "";
	var result = {};
	
	restCall = {};
	restCall.url = constructAmUri(amServer) + "/json/realms/" + amServer.realm + "/authenticate";

	restCall.headers = { "Content-Type" 	  : "application/json", 
			     "Accept-API-Version" : "resource=2.0, protocol=1.0",
			     "X-OpenAM-Username"  : amServer.username,
			     "X-OpenAM-Password"  : amServer.password};
	restCall.body = "{}";
	restCall.method = "POST";
	
	ssoToken = executeRest(restCall).tokenId;
	amServer.ssoToken = ssoToken;
	amServer.loggedin = true;	

	return ssoToken;
}

//Call AM in order to create the authorization policy
function AM_policy_create(amServer, policyData){
	
	var result = {};
	var ssoToken = amServer.ssoToken;
	
	restCall = {};
	restCall.url = constructAmUri(amServer) + "/json/realms/" + amServer.policyRealm + "/policies?_action=create";

	restCall.headers = { "contentType" 	    : "application/json", 
			     "Accept-API-Version"   : "protocol=1.0",
			     "iPlanetDirectoryPro"  : ssoToken};
	restCall.body = JSON.stringify(policyData);
	restCall.method = "POST";

	executeRest(restCall);

	return;
	
}

//Call AM in order to delete the authorization policy
function AM_policy_delete(amServer, inputAccountIntentId){

        var result = {};
        var ssoToken = amServer.ssoToken;

        restCall = {};
        restCall.url = constructAmUri(amServer) + "/json/realms/" + amServer.policyRealm + "/policies/" + inputAccountIntentId;

	console.log("[DEBUG]: url to delete - " + restCall.url);

        restCall.headers = { "contentType" : "application/json",
                             "Accept-API-Version"    : "protocol=1.0",
                             "iPlanetDirectoryPro"   : ssoToken};
        restCall.method = "DELETE";

        executeRest(restCall);

        return;

}

function executeRest(restCall){
	var result = {};
	
	try {
		result = openidm.action("external/rest", "call", restCall);
	}
 
	catch (e) { 
		console.log("Got exception: " + e);
	}
	
	return result;
	
}

function getHeader(thisHeader){
	return context.http.headers[thisHeader];	
}

function AM_dynamic_client_reg(amServer, clientInfo){

	var result = {};

	restCall = {};
	restCall.url = constructAmUri(amServer) + "/oauth2/realms/root/realms/" + amServer.clientRealm + "/register"

	console.log("[DEBUG]: url to register - " + restCall.url);

    // fix up array
	//var redirect_uris = { "testuris": [ "https://www.google.com" ] };
	//console.log("uris " + JSON.stringify(redirect_uris));

	restCall.headers = {
		"contentType" : "application/json"
	};
	restCall.method = "POST";
	restCall.body = "" + clientInfo;
	console.log("[DEBUG] Posting data " + restCall.body)

	result = executeRest(restCall);

	console.log("got result " + result)

	return result;

}

