const express   = require('express');
const router    = express.Router();
const database  = require('../class/database');


router.get('/clear', (request, response) => {
  let count = database.deleteNonAdminUsers();
/*
   
    Object.keys(users).forEach(function(key) {
        delete database[key];
      });*/

    response.json(count + " users removed from the database");
})

router.get('/users', (request, response) => {
  let users = database.getUsers();
  let text = users.length + " Users registered.";
    response.json(text);
})

router.get('/devices', (request, response) => {
  response.json(database.getDevices());
})

module.exports = router;
