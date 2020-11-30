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
 
load("script/obie/ob_payment_intent.js");
load("script/obie/ob_account_access_intent.js");
load("script/obie/ob_tpp.js");
load("script/obie/ob_utils.js");

(function(){
	d = new Date();
	s = d.getTime();
	console.log("[DEBUG] Main OB Handler - " + s);
    
	returnObject = {};
	
	switch (thisUriComponent("APPLICATION")) {

                case "obPaymentIntent":
                        returnObject = payment_intent_main();
                        break;
			
		case "obAccountAccessIntent":
			returnObject = account_access_intent_main();
			break;

                case "obTpp":
                        returnObject = create_tpp_main();
                        break;

	}
	
	return returnObject;

})();
