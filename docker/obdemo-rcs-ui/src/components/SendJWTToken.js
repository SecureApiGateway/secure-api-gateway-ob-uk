import React, { Component } from 'react';
class SendJWTToken extends Component{
      constructor(props){
        super(props);
      }

      componentDidMount(){
        const result=this.props.contentObj;
        console.log('result componentDidMount: ', result.redirectUri );
        document.redirectForm.submit();
      }
      render(){
        const result=this.props.contentObj;
          return(
            <div>
              <form name="redirectForm" action={result.redirectUri} onSubmit={this.handleSubmit}
                method="post">
                <input name="consent_response" type="hidden" defaultValue={result.consentJwt}/>
                </form>
            </div>
          );
      }
    }

    export default SendJWTToken;
