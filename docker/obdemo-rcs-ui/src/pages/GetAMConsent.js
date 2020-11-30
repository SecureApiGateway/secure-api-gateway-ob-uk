import React, { Component } from 'react';
import AccountsList from './../components/AccountsList.js';
import ScopesList from './../components/ScopesList.js';
import PISPDetails from './../components/PISPDetails.js';
import AISPDetails from './../components/AISPDetails.js';
import SendJWTToken from './../components/SendJWTToken.js'
import * as qs from 'query-string';

class GetAMConsent extends Component {
	constructor(props) {
	super(props);
  this.handleSubmit = this.handleSubmit.bind(this);
	this.handleClick = this.handleClick.bind(this);
}

	myCallback = (dataFromChild) => {
			  this.setState({ selectedAccount: dataFromChild });
	 };
	state ={
			isLoading:true,
			result:{},
			redirect: false,
			redirectUri:'',
			consentJwt:'',
			selectedAccount:new Set(),
			decisionChoose:''
	};
	getArrayOfValue(nodeOfArray){
		let items=[];
		if(nodeOfArray){
			for (var i = 0; i < nodeOfArray.length; i++) {
			 if(nodeOfArray[i].value&&nodeOfArray[i].value!=="")	items.push(nodeOfArray[i].value);
			}
		if(nodeOfArray !== null && typeof nodeOfArray === 'object' && nodeOfArray.value!=="") {
				items.push(nodeOfArray.value);
		}
	}
		console.log("items: ",items);
		return items;
	}

	sendConsentBack(colectedData){
		// const url = process.env.REACT_APP_API_URL+'/api/rcs/consent/sendconsent';
        const url = '/rcs-api/api/rcs/consent/sendconsent';
		fetch(url, {
		redirect: 'follow',
		method: 'POST',
		headers: {
								'Accept': 'application/json',
								'Content-Type': ' application/json'
							},
		body: JSON.stringify(colectedData)
		}).then(response => response.json())
		.then(response => {
			console.info("success redirect url: " + response.redirectUri);
			console.info("consentJwt url: " + response.consentJwt);
			this.setState({	redirect: true, redirectUri:response.redirectUri, consentJwt:response.consentJwt});
			//window.location.replace(response.redirectUri);
		})
		.catch(function(err) {
				console.info(err + " url: " + url);
		});
	}

	checkIfIsAutoAccept(responseResult){
		if(responseResult.flow==='aisp_auto_accept'){
			const data = { consent_request:responseResult.consentRequest,
				 decision:true,
				 //claims:responseResult.claims,
				 claims:"",
				 flow:responseResult.flow,
				 scope:responseResult.scopeList
				}
				console.log("checkIfIsAutoAccept ",data);
					this.sendConsentBack(data);
		}
	}

  handleSubmit(event){
		console.log("this.state.selectedAccount: ",this.state.selectedAccount);
      event.preventDefault();
      console.log("decision: ",this.state.decisionChoose);
			const scopeItems = this.getArrayOfValue(event.target.scope);
			console.log("scopeItems: ",scopeItems);
			//const accountItems = this.state.selectedAccount?[this.state.selectedAccount]:this.getArrayOfValue(event.target.account);
			const accountItems = Array.from(this.state.selectedAccount);
			console.log("accountItems: ",accountItems);
			const data = { consent_request:(event.target.consent_request)?event.target.consent_request.value:"",
				 decision:this.state.decisionChoose,
				 claims:(event.target.claims)?event.target.claims.value:"",
				 flow:(event.target.flow)?event.target.flow.value:"",
				 scope:scopeItems,
				 account:accountItems
			  }
      this.sendConsentBack(data);


  }
    handleClick(event){
			 this.setState({ decisionChoose: event.target.value });
    }


	async componentDidMount(){

    const urlQueryParam=this.props.location.search;
    const urlParamConsentRequest = qs.parse(urlQueryParam);
    console.log('consent_request:',urlParamConsentRequest.consent_request);
		const encodedRequestConsent=encodeURIComponent(urlParamConsentRequest.consent_request);
		console.log('REACT_APP_API_URL',process.env.REACT_APP_API_URL)
		// const response = await fetch(process.env.REACT_APP_API_URL+`/api/rcs/consent?consent_request=${encodedRequestConsent}`,{
        const response = await fetch(`/rcs-api/api/rcs/consent?consent_request=${encodedRequestConsent}`,{
			method: 'get',
			headers: {
									'Accept': 'application/json',
                  'Content-Type': ' application/json'
                }

		});
		console.log('response:',response);
		const body = await response.json();
		console.log('body:',body);
		this.setState({result:body, isLoading:false});
		this.checkIfIsAutoAccept(body);
	}

  render() {
	const {result,isLoading,redirect}=this.state;
	if(isLoading){
		return (
      <p className="d-flex justify-content-center"> Loading...</p>
  );
	}
	if(!redirect&&!result.errorDetails){
    return (
      <div id="content" className="container">
		<div className="row">
			<div className="col"></div>
			<div className="col-6 mat-card">
				<div className="text-center">
					<img className="forgerock-customer-logo" src="/rcs/images/logo.svg"
						width="230" height="0"></img>
				</div>
				<h6>Permissions asked by the application :   {result.clientName} </h6>

				<div className="divider"></div>

				<div id="accounts-list">
					<form action="/api/rcs/consent/sendconsent" onSubmit={this.handleSubmit}
						method="post">

            <ScopesList contentObj={result} />
						<AccountsList contentObj={result} callbackFromParent={this.myCallback}  />
            <PISPDetails contentObj={result} />
            <AISPDetails contentObj={result} />

						<input type="hidden" name={result.consentRequestFieldName}
							value={result.consentRequest} /> <input type="hidden"
							name="flow" value={result.flow} />
							<input type="hidden" name="claims" value={result.initiationClaims} />
						<div className="divider"></div>
						<div className="form-group row mat-card-actions">
							<div className="col-xs-12">
								<button name='decisionDeny' onClick={this.handleClick} value="deny" type="submit"
									className="btn mat-stroked-button">Deny</button>
								<button name='decision'  onClick={this.handleClick} value="allow" type="submit"
									className="btn raised-button" >Allow</button>
							</div>
						</div>
					</form>
				</div>
			</div>
			<div className="col"></div>
		</div>
	</div>
    );
	} else if(redirect&&!result.errorDetails) {
		  return (
				<div id="content" className="container">
					<SendJWTToken contentObj={this.state} />
				</div>
			);
	}

	if(result.errorDetails){
		return (
			<div id="content" className="container">
		<div className="row">
			<div className="col"></div>
			<div className="col-6 mat-card">
				<div className="text-center">
					<img className="forgerock-customer-logo" src="/images/logo.svg"
						width="230" height="0"></img>
				</div>


				<div className="divider"></div>
				<h6 className="alert alert-danger alert-dismissible fade show"	> <strong>Error!</strong>   {result.errorDetails.errorMessage} </h6>
				<div id="accounts-list">

				</div>
			</div>
			<div className="col"></div>
		</div>
	</div>
  );
	}

  }
}
export default GetAMConsent;
