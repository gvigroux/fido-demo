const low = require('lowdb');
const utils    = require('./webauthn-utils');
const FileSync = require('lowdb/adapters/FileSync');


const adapter = new FileSync('database/credentials.json');
const database = low(adapter);
const deviceDatabase = low(new FileSync('database/devices.json'));

// Set some defaults
database.defaults({ users: [], credentials: [] }).write()
deviceDatabase.defaults({devices: []}).write();

function getDevice(aaguid)
{
    return deviceDatabase.get('devices').find({ aaguid: aaguid.replace(/-/g,"") }).value();
}

function createUser(id, name, displayName, credentialsCount)
{
    let data = {id: id, name: name, displayName: displayName, credentialsCount: credentialsCount};
    database.get('users').push(data).write()
    return data;
}

function getUserByName(name)
{
    return database.get('users').find({ name: name }).value();
}

function getCredential(id)
{
    return database.get('credentials').find({ id: id }).value(); 
}

function getCredentials(username)
{
    let credentials = database.get('credentials').filter({ username: username }).value();
    // Clone the array to not modify the database
    let cloneCredentials = [...credentials];
    cloneCredentials.forEach((credential) => {
        let device = getDevice(credential.aaguid);
        if(device == null) 
            device = getDevice("Unknown");
        credential.deviceName   = device.name;
        credential.deviceImage  = device.image;
    });
    return cloneCredentials;
}

function createCredential(id, username, data)
{
    database.get('credentials').push({ id: id, username: username, aaguid: data.aaguid, cert: data.cert, counter: data.counter, fmt: data.fmt, publicKey: data.publicKey, credID: data.credID}).write();
    return data;
}

function save()
{
    database.write();
}


module.exports = {getUserByName, getCredential, getCredentials, createUser, createCredential, save};