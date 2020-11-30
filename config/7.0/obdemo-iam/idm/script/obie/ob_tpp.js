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

//Create OB TPP IDM Endpoint - main method
function create_tpp_main(){
	
	if (request.method == "create") {
		console.log("[DEBUG] DATA obTpp request: "+ request);
		console.log("[DEBUG] DATA obTpp request content: "+ request.content);
		regTppResult = registerTpp(request.content);


		clientDetails = JSON.parse(regTppResult);

		ssa = parseJwt(clientDetails.software_statement);
		var clientName = ssa.org_name;

		// var clientName = clientDetails.client_name;
		// var clientName = clientDetails.software_statement.org_id;
		var clientCertId = ssa.org_id;
		var clientIdentifier = clientDetails.client_id;
		var clientSsa = clientDetails.software_statement;

		console.log("[DEBUG] client id " + clientIdentifier);
		console.log("[DEBUG] client name " + clientName);

		regData = {
			"name" : clientName,
			"certId" : clientCertId,
			"ssa": clientSsa,
			"identifier": clientIdentifier
		}

		createTppObjectResult = createTpp(regData);

		return regTppResult;
	}
	else {
		throw { code : 500, message : "Invalid request - only POST implemented for createTpp" };
	}	
}


// Hit AM with registration request, then create in IDM

function registerTpp(registrationData) {
    var regResult = AM_dynamic_client_reg(amServer, registrationData);
    return regResult;
}

//Create TPP object and relationship with SSA 
function createTpp(tppData){
	var returnObject = {};
    	var newTppObject = {};
	var newTppSsaObject = {};
    	returnObject.status = "FAILED";
    	ssaId = "";
	tppId = "";

	if ((typeof tppData.identifier == 'string') && (typeof tppData.ssa == 'string')) {
        
	        tppID = findTppByIdentifier(tppData.identifier);
		ssaId = findTppSsaByValue(tppData.ssa);		

        	if (!tppID.equals("-1")){          
			//Create the SSA managed object in IDM
			newTppSsaObject.ssa = tppData.ssa;
                        ssaId = openidm.create(CONFIG_managedObjects.obTppSsa, null, newTppSsaObject)._id;
            		console.log("[DEBUG]: SSA ID created: " + ssaId);

			//Update existing TPP managed object in IDM with the new SSA
			var newTppObjectArray = [];
			newTppObject.operation = "add";
       			newTppObject.field = "/ssas/-";
			var ssaTpp = {};
			ssaTpp._ref = CONFIG_managedObjects.obTppSsa + "/" + ssaId;
   			newTppObject.value = ssaTpp;    
       			newTppObjectArray.push(newTppObject);
		
       			returnObject.id = openidm.patch(CONFIG_managedObjects.obTpp + "/" + tppID, null, newTppObjectArray)._id;
			console.log("[DEBUG]: TPP ID that was updated with the new SSA: " + returnObject.id);            	
		
			console.log("[DEBUG]: " + JSON.stringify(newTppObject, null,4));
			returnObject.status = "SUCCESS";
			returnObject.reason = "[IDM] OB TPP Managed Object was successfully updated.";
			returnObject.code = 201;
        	}
        	else {
			if (ssaId.equals("-1")){
				//Create the SSA managed object in IDM
                        	newTppSsaObject.ssa = tppData.ssa;
                        	ssaId = openidm.create(CONFIG_managedObjects.obTppSsa, null, newTppSsaObject)._id;
				console.log("[DEBUG]: SSA ID created: " + ssaId);
                	}

			//Create new TPP managed object in IDM with the associated SSA
                        newTppObject.identifier = tppData.identifier;
			newTppObject.certId = tppData.certId;
                        newTppObject.name = tppData.name;
                        newTppObject.created = generateTimestamp();
                        newTppObject.ssas = [{ "_ref" : CONFIG_managedObjects.obTppSsa + "/" + ssaId}];

                        returnObject.id = openidm.create(CONFIG_managedObjects.obTpp, null, newTppObject)._id;
			console.log("[DEBUG]: TPP ID that was created with the associated SSA: " + returnObject.id);

                        console.log("[DEBUG]: " + JSON.stringify(newTppObject, null,4));
			returnObject.status = "SUCCESS";
			returnObject.reason = "[IDM] OB TPP Managed Object was successfully created.";
			returnObject.code = 201;
        	}
	}
	else{
		returnObject.reason = "[IDM ERROR] identifier and ssa must be specified as a string";
		returnObject.code = 500;
	}

	return returnObject;
}


//Search if the TPP Object is already created in IDM
function findTppByIdentifier(tppIdentifier){
    
    var ID = "-1";
    var resultObject =  openidm.query(CONFIG_managedObjects.obTpp, { "_queryFilter": "/identifier eq \""+ tppIdentifier +  "\""}, ["_id"]);   

    if (resultObject.resultCount == 1 ){
        ID = resultObject.result[0]._id
    }

    console.log("[DEBUG] findTppByIdentifier response: " + ID);
    return ID;
}


//Search if the TPP SSA Object is already created in IDM
function findTppSsaByValue(tppSsa){

    var ID = "-1";
    var resultObject =  openidm.query(CONFIG_managedObjects.obTppSsa, { "_queryFilter": "/ssa eq \""+ tppSsa +  "\""}, ["_id"]);

    if (resultObject.resultCount == 1 ){
        ID = resultObject.result[0]._id
    }

    console.log("[DEBUG] findTppSsaByValue response: " + ID);
    return ID;
}
