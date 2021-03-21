const express  = require('express');
const utils    = require('../class/webauthn-utils');
const router   = express.Router();
const database = require('../class/database');


// Login page
router.get('/', (request, response) => {
    response.render('index');
})

// Register new token page
router.get('/register', (request, response) => {
    response.render('register');
})

// Main page with tokens described
router.get('/main', (request, response) => {
    if(!request.session.loggedIn)
        return response.redirect('/');

    let logType = 0;
    /*
    if( request.session.authenticate.clientData !== undefined )
        logType = 1;
    else if( request.session.register.credentials_create_parameters !== undefined )
        logType = 2;*/

    let log = { // Authenticate
                clientData: JSON.stringify(request.session.authenticate.clientData,null,2), 
                assertion: JSON.stringify(request.session.authenticate.assertion,null,2), 
                assertion_response: JSON.stringify(request.session.authenticate.assertion_response,null,2),
                // Register
                credentials_create_parameters: JSON.stringify(request.session.register.credentials_create_parameters,null,2),
                credentials_create_response: JSON.stringify(request.session.register.credentials_create_response,null,2),
                parsedClientData: JSON.stringify(request.session.register.parsedClientData,null,2),
                //relyingPartyResponse: JSON.stringify(request.session.register.relyingPartyResponse,null,2)
                relyingPartyResponse: request.session.register.relyingPartyResponse
            }

    user = request.session.user;
    authenticators = database.getCredentials(user.name);
    response.render('main', {name : user.displayName, authenticators: authenticators, log: log, logType: logType});
})

//Logs user out
router.get('/logout', (request, response) => {
    request.session.loggedIn = false;
    request.session.username = undefined;
    response.redirect("/");
})


module.exports = router;
