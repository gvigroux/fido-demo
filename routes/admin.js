const express   = require('express');
const router    = express.Router();
const database  = require('../class/database');


router.get('/clear', (request, response) => {
    let length = Object.keys(database).length || 0;
   
    Object.keys(database).forEach(function(key) {
        delete database[key];
      });

    response.json(length + " users removed from the database");
})

router.get('/users', (request, response) => {
    let length = Object.keys(database).length || 0;
   
    let text = "";
    Object.keys(database).forEach(function(key) {
        text += key + " with " + database[key].authenticators.length + " autenticators.";
      });

    response.json(text);
})

module.exports = router;
