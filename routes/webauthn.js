const express   = require('express');
const utils     = require('../class/webauthn-utils');
const config    = require('../config.json');
const base64url = require('base64url');
const User      = require('../class/user');
const router    = express.Router();
const database  = require('../class/database');


// ****************************************************************
// Create a user and add a new token

router.post('/getMakeCredentialsChallenge', (request, response) => {

    let user = null;

    // Reset logs
    request.session.register = {};
    request.session.authenticate = {};

    // TODO
    if( request.session.loggedIn && request.session.user !== undefined) {
        user = request.session.user;
    }
    // New user
    else {
        if(!request.body || !request.body.name || !request.body.displayName)
            return response.json({'message': 'Missing name field!'})
    
        // Check if user exist in database
        if( User.loadFromDatabase(request.body.name) != null ) 
            return response.json({'message': 'User already exists!'})
        user = new User(request.body.name, request.body.displayName); 
        request.session.user = user;
    }
    
    let requireResidentKey = false;
    if( request.body.requireResidentKey === "yes" ) requireResidentKey = true;
    
    let challengeMakeCred     = utils.generateServerMakeCredRequest(request.body.userVerification, requireResidentKey, user.id, user.name, user.displayName)
    request.session.challenge = challengeMakeCred.challenge;
    request.session.register.credentials_create_parameters = challengeMakeCred;
    response.json(challengeMakeCred)
})


// ****************************************************************
// Called after new registration

router.post('/verifyAttestation', (request, response) => {

    if(!request.body       || !request.body.response
    || !request.body.type  || request.body.type !== 'public-key' )
        return response.json({'message': 'Response missing one or more of response/type fields, or type is not public-key!'})

    // Format data
    let clientData   = JSON.parse(base64url.decode(request.body.response.clientDataJSON));

    // Check challenge...
    if(clientData.challenge !== request.session.challenge)
       return response.json({'message': 'Challenges don\'t match!'})

    // ...and origin
    if(clientData.origin !== config.origin)
        return response.json({'message': 'Origins don\'t match with: ' + clientData.origin})

    let result = utils.verifyAuthenticatorAttestationResponse(request.body);
    if(result.verified) {
        let user = request.session.user;
        User.saveToDatabase(user);
        database.createCredential(result.authrInfo.credID, user.name, result.authrInfo);            
        request.session.loggedIn = true;
        request.session.register.credentials_create_response = request.body;
        request.session.register.parsedClientData = clientData;
        request.session.register.relyingPartyResponse = base64url.decode(request.body.response.attestationObject);
        return response.json({/*"clientData": clientData*/})
    }
    return response.json({'message': 'Can not authenticate signature! [' + result.fmt + "]"})
})




// ****************************************************************
// Authentication 1/2: Get navigator.credentials.get() options

router.post('/getPublicKeyCredentialRequestOptions', (request, response) => {

    // Reset logs
    request.session.register = {};
    request.session.authenticate = {};

    if(!request.body)
        return response.json({'message': 'Invalid request'})
          
    let authenticators = [];
    // When no Resident Key, we need to specify the authenticator
    if( request.body.requireResidentKey !== "yes" ) {
        if(!request.body.name)
            return response.json({'message': 'No user name'})
        authenticators = database.getCredentials(request.body.name);
    }

    let assertion    = utils.generateServerGetAssertion(request.body.userVerification, authenticators)
    request.session.authenticate.assertion = assertion;
    return response.json(assertion)
})


// ****************************************************************
// Authentication 2/2: Check AuthenticatorAssertionResponse

router.post('/verifyAuthenticatorAssertionResponse', (request, response) => {

    if(!request.body       || !request.body.response
    || !request.body.type  || request.body.type !== 'public-key' )
        return response.json({'message': 'Response missing one or more of response/type fields, or type is not public-key!'})

    // Format data
    let clientData   = JSON.parse(base64url.decode(request.body.response.clientDataJSON));

    // Check challenge...
    if(clientData.challenge !== request.session.authenticate.assertion.challenge)
       return response.json({'message': 'Challenges don\'t match!'})

    // ...and origin
    if(clientData.origin !== config.origin)
        return response.json({'message': 'Origins don\'t match with: ' + clientData.origin})

    let credential = database.getCredential(request.body.id);
    result = utils.verifyAuthenticatorAssertionResponse(request.body, [credential]);
    if(result.verified) {
        request.session.user = User.loadFromDatabase(credential.username);
        database.save();
        request.session.loggedIn = true;
        request.session.authenticate.clientData = clientData;
        request.session.authenticate.assertion_response = request.body.response;
        return response.json({})
        //return response.json({"clientData": clientData , "assertion": request.session.authenticate.assertion , "assertion_response" : request.body.response })
    }
    return response.json({'message': 'Can not authenticate signature! [' + result.fmt + "]"})
})




// ****************************************************************
// Called after Register and Login
/*
router.post('/response', (request, response) => {

    if(!request.body       || !request.body.id
    || !request.body.rawId || !request.body.response
    || !request.body.type  || request.body.type !== 'public-key' )
        return response.json({'status': 'failed','message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'})

    let webauthnResp = request.body
    let clientData   = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

    // Check challenge...
    if(clientData.challenge !== request.session.challenge)
       return response.json({'status': 'failed', 'message': 'Challenges don\'t match!'})

    // ...and origin
    if(clientData.origin !== config.origin)
        return response.json({'status': 'failed', 'message': 'Origins don\'t match with: ' + clientData.origin})

    let result  = {'fmt': 'N/A'};

    // Register response
    if(webauthnResp.response.attestationObject !== undefined) {
        // This is create cred 
        result = utils.verifyAuthenticatorAttestationResponse(webauthnResp);
        if(result.verified) {
            //let user = database.get(request.session.username);
            //user.authenticators.push(result.authrInfo);
            //user.registered = true;
            //database.save();
            database.setCredential(result.authrInfo.credID, request.session.username, result.authrInfo);
        }
    } 
    // Login response
    else if(webauthnResp.response.authenticatorData !== undefined) {
        let credential = database.getCredential(webauthnResp.id);
        result = utils.verifyAuthenticatorAssertionResponse(webauthnResp, [credential]);
        if(result.verified)
            request.session.username = credential.username;
            database.save();
    } else {
        return response.json({'status': 'failed','message': 'Can not determine type of response!','log': result.log})
    }

    if(result.verified) {
        request.session.loggedIn = true;
        response.json({ 'status': 'ok' })
    } else {
        let message = 'Can not authenticate signature! [' + result.fmt + "]";
        if(( result.message !== undefined) && ( result.message.length > 0)) message = result.message;

        response.json({'status': 'failed','message': message,'log': result.log})
    }
})
*/




module.exports = router;
