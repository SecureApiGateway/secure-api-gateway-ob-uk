import React, { Component } from 'react';

class PISPDetails extends Component{
      constructor(props){
        super(props);
      }
      render(){
        const result=this.props.contentObj;
        if(result.flow==='pisp'){
          return(
            <div>
              <p>Payment Details</p>
              {result.obPaymentConsentPISP.data.initiation.debtorAccount&&
                <div>
                <p>
                Name: {result.obPaymentConsentPISP.data.initiation.debtorAccount.name}
                </p>
                <p>
                Identification: {result.obPaymentConsentPISP.data.initiation.debtorAccount.identification}
                </p>
                </div>
              }
              <p>
                Amount: <span>{result.obPaymentConsentPISP.data.initiation.instructedAmount.amount}</span>
              </p>
              <p>
                Currency: <span>{result.obPaymentConsentPISP.data.initiation.instructedAmount.currency}</span>
              </p>
              <p>
                Status: <span>{result.obPaymentConsentPISP.status}</span>
              </p>
            </div>
          );
        } else {
          return(
            <div></div>
          );
        }
      }
}

export default PISPDetails;
