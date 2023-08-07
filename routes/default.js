const express  = require('express');
const utils    = require('../class/webauthn-utils');
const router   = express.Router();
const database = require('../class/database');
const fs       = require('fs');
const multer   = require('multer');
const upload   = multer({ storage: multer.memoryStorage() });
const path     = require('path');

// Login page
router.get('/', (request, response) => {
    response.render('login');
})

// Register new token page
router.get('/register', (request, response) => {

    /*
    let log = { 
        // Register
        credentials_create_parameters: JSON.stringify(request.session.register.credentials_create_parameters,null,2),
        credentials_create_response: JSON.stringify(request.session.register.credentials_create_response,null,2),
        parsedClientData: JSON.stringify(request.session.register.parsedClientData,null,2),
        relyingPartyResponse: JSON.stringify(request.session.register.relyingPartyResponse,null,2),
        signatureDetails: JSON.stringify(request.session.register.signatureDetails,null,2)
    }*/

    response.render('register');
})

// Contact
router.get('/contact', (request, response) => {
    response.render('contact');
})


// Main page with tokens described
router.get('/main', (request, response) => {
    if(!request.session.loggedIn)
        return response.redirect('/');

    let logType = 0;

    if( request.session.authenticate.clientData !== undefined )
        logType = 1;
    else if( request.session.register.credentials_create_parameters !== undefined )
        logType = 2;

    // Remove logs
    logType = 0;

    let log = { // Authenticate
                clientData: JSON.stringify(request.session.authenticate.clientData,null,2), 
                assertion: JSON.stringify(request.session.authenticate.assertion,null,2), 
                assertion_response: JSON.stringify(request.session.authenticate.assertion_response,null,2),
                // Register
                credentials_create_parameters: JSON.stringify(request.session.register.credentials_create_parameters,null,2),
                credentials_create_response: JSON.stringify(request.session.register.credentials_create_response,null,2),
                parsedClientData: JSON.stringify(request.session.register.parsedClientData,null,2),
                relyingPartyResponse: JSON.stringify(request.session.register.relyingPartyResponse,null,2),
                signatureDetails: JSON.stringify(request.session.register.signatureDetails,null,2)

                //relyingPartyResponse: request.session.register.relyingPartyResponse
            }

    user = request.session.user;
    authenticators = database.getCredentials(user.id);
    response.render('main', {name : user.displayName, authenticators: authenticators, log: log, logType: logType});
})

//Logs user out
router.get('/logout', (request, response) => {
    user = request.session.user;
    request.session.loggedIn = false;
    request.session.user = undefined;
    response.redirect("/?user=" + user.name);
})

// Login page
router.get('/devices', (request, response) => {
    devices = database.getDevices();
    images = fs.readdirSync(__dirname + "/../static/img/product/");
    response.render('devices', {devices: devices, images: images});
})

router.post('/deleteDevice', (request, response) => {

    if(!request.body)
        return response.json({'message': 'Invalid request'})
          
    if(!request.body.aaguid)
        return response.json({'invalidField': 'aaguid'})

    // No specific check on AAGUID, we remove whatever we found
    database.deleteDevice(request.body.aaguid);

    return response.json({})
})


router.post('/addDevice', (request, response) => {

    if(!request.body)
        return response.json({'message': 'Invalid request'})
    
    if(!request.body.name)
        return response.json({'invalidField': 'name'})
            
    if(!request.body.aaguid)
        return response.json({'invalidField': 'aaguid'})

    if( !database.isAAGUIDValid(request.body.aaguid) )
        return response.json({'invalidField': 'aaguid'})

    if(!request.body.image)
        return response.json({'invalidField': 'image' })


    database.addDevice(request.body.aaguid, request.body.name, request.body.image);

    return response.json({})
})




router.post('/addImage', upload.single('imageImport'), (request, response) => {

    if(!request.body)
        return response.json({'message': 'Invalid request'})

    if(!request.file)
        return response.json({'invalidField': 'imageImport' })

    if (fs.existsSync('static/img/product/' + request.file.originalname))
        return response.json({'invalidField': 'File already exists' })
    
    fs.writeFileSync('static/img/product/' + request.file.originalname, request.file.buffer);

    return response.redirect('/devices');
})



module.exports = router;
