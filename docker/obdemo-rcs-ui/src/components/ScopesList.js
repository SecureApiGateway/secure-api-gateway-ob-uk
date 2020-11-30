import React, { Component } from 'react';

class ScopesList extends Component{
  constructor(props) {
      super(props);
    }
    render(){
      const flow=this.props.contentObj.flow;
        if(flow!=='pisp'&&flow!=='aisp'){
          return(
            <div>
							<p>Do you consent to approve scopes:</p>
							<ul className="no-list-type">
                  {this.props.contentObj.scopeList&&this.props.contentObj.scopeList.map((scope,index)=>
                    <li key={index}>
                      <div className="custom-control custom-checkbox">
                    <input checked="checked" type="checkbox" id={scope}
                      name="scope" className="custom-control-input" value={scope} />
                    <label className="custom-control-label" for={scope}
                      >{scope}</label>
                      </div>
                    </li>
                  )}
							</ul>
						</div>
          );
        } else  if(flow==='pisp'||flow==='aisp'||flow==='aisp_auto_accept'){
          return(
          <div>
            {this.props.contentObj.scopeList&&this.props.contentObj.scopeList.map((scope,index)=>
              <input type="hidden" name="scope" value={scope} key={index}/>
            )}
          </div>
        );
        } else{
          return(
            <div></div>
          );
        }
    }
}

export default ScopesList;
