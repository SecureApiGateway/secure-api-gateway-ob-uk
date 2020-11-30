import React, { Component } from 'react';

class AISPDetails extends Component{
      constructor(props){
        super(props);
      }
      render(){
        const result=this.props.contentObj;
        if(result.flow==='aisp'){
          return(
            <div className="accordion"
              id="accordionExample">
              <div className="card no-color-card">
                <div className="card-header" id="headingOne">
                  <h2 className="mb-0">
                    <button className="btn btn-link card-header-holder" type="button"
                      data-toggle="collapse" data-target="#collapseOne"
                      aria-expanded="true" aria-controls="collapseOne">
                      Permissions</button>
                  </h2>
                </div>

                <div id="collapseOne" className="collapse show"
                  aria-labelledby="headingOne" data-parent="#accordionExample">
                  <div className="card-body">
                    <ul className="no-list-type">
                    {result.obAccountsAccessConsentAIPS.data.permissions.map((permisionItem,index)=>
                      <li key={index}>
                        <div className="custom-control custom-checkbox">
                          <p>{permisionItem}</p>
                        </div>
                      </li>
                    )}
                    </ul>
                  </div>
                </div>
              </div>

            </div>
          );
        } else {
          return(
            <div></div>
          );
        }
      }
}

export default AISPDetails;
