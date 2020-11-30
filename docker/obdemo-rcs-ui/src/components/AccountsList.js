
import React from 'react';

class AccountsList extends React.Component{
  constructor(props) {
      super(props);
    this.handleOptionChange=this.handleOptionChange.bind(this);
    }

    componentWillMount = () => {
      this.selectedCheckboxes = new Set();
    }

    handleOptionChange(event){
  	  console.log("Selecte account:", event.target.type);
  	  this.setState({
  	  selectedAccount:event.target.value
  	  });
      if(event.target.type==="radio"){
        this.selectedCheckboxes.clear();
        this.selectedCheckboxes.add(event.target.value)
      }else{
        if (this.selectedCheckboxes.has(event.target.value)) {
          this.selectedCheckboxes.delete(event.target.value);
        } else {
          this.selectedCheckboxes.add(event.target.value);
        }
      }

      console.log("selectedCheckboxes:",this.selectedCheckboxes);
      this.props.callbackFromParent(this.selectedCheckboxes);
  	}

render(){
  const flow=this.props.contentObj.flow;
    if((flow==='pisp')||flow==='aisp'){
      if(flow==='aisp'||(this.props.contentObj.obPaymentConsentPISP
        &&!this.props.contentObj.obPaymentConsentPISP.data.initiation.debtorAccount) ){
      return(
        <div>
        <p>Accounts:</p>
        <ul className="no-list-type">
         {this.props.contentObj.accountList&&this.props.contentObj.accountList.map((account,index)=>
             <li  key={index}>
             <div className={(flow==='pisp'?'custom-radio':flow==='aisp'?'custom-checkbox':'')+' custom-control custom-control-inline'} >
            <input type={flow==='pisp'?'radio':flow==='aisp'?'checkbox':''} id={account.accountId} required={flow==='pisp'?'required':''}
              name="account" className="custom-control-input" onChange={this.handleOptionChange}
              defaultValue={account.accountId} /> <label className="custom-control-label"
              htmlFor={account.accountId} >{account.currency} {account.nickname}({account.account&&account.account.length>=1&&account.account[0].identification})</label>
          </div>
          </li>
          )}

        </ul>
        <div className="divider"></div>
        </div>
      );
  } else {
      return(
        <div>
            <input type="hidden" name="account" defaultValue={this.props.contentObj.obPaymentConsentPISP&&this.props.contentObj.obPaymentConsentPISP.data.initiation.debtorAccount.identification} />
        </div>
      );
  }
  }  else {
    return(
      <div></div>
    );
  }
}
}
export default AccountsList;
