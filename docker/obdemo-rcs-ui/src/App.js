import React, { Component } from 'react';
import GetAMConsent from './pages/GetAMConsent.js';
import SendJWTToken from './components/SendJWTToken.js';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';

class App extends Component {
	render() {
     return (
       <Router basename='/rcs'>
         <Switch>
           <Route path='/' exact={true} component={GetAMConsent}/>
           <Route path='/api/rcs/consent/' exact={true} component={GetAMConsent}/>
					 <Route path='/api/rcs/redirect' exact={true} component={SendJWTToken}/>
         </Switch>
       </Router>
     )
   }
 }

export default App;
