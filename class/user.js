const utils     = require('./webauthn-utils');
const database  = require('../class/database');


class User {
    constructor(name, displayName) {
        this.id     = utils.randomBase64URLBuffer();
        this.name   = name;
        if( displayName.length == 0)
            this.displayName = name;
        else
            this.displayName = displayName;
        this.credentialsCount = 0;
    }

    static saveToDatabase(user) {
        database.createUser(user.id, user.name, user.displayName, user.credentialsCount);
    }

    static loadFromDatabase(name) {
        return database.getUserByName(name);
    }

    static exists(name) {
        return (database.getUserByName(name) != null);
    }

}

module.exports = User;