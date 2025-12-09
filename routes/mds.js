const jwt_decode    = require('jwt-decode');
const fs            = require('fs');
const express       = require('express');
const router        = express.Router();


router.get('/', (request, response) => {
    response.render('mds');
})

var mds = ""


router.get('/get', (request, response) => { 
    
    if( mds == "" ) {
        let data    = fs.readFileSync('static/mds/blob.jwt').toString();
        mds         = jwt_decode(data);
        mds.entries = mds.entries.filter((entry) => typeof entry.aaguid !== 'undefined');
    }
    return response.json(mds)
})

module.exports = router;
