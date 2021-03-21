const utils     = require('./webauthn-utils');
const database  = require('../class/database');


class User {
    constructor(name, displayName) {
        this.id     = utils.randomBase64URLBuffer();
        this.name   = name;
        this.displayName = displayName;
        this.credentialsCount = 0;
    }

    static saveToDatabase(user) {
        database.createUser(user.id, user.name, user.displayName, user.credentialsCount);
    }

    static loadFromDatabase(name) {
        return database.getUserByName(name);
    } 

}

module.exports = User;