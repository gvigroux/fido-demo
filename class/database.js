const low = require("lowdb");
const utils = require("./webauthn-utils");
const FileSync = require("lowdb/adapters/FileSync");

const adapter = new FileSync("database/credentials.json");
const credDatabase = low(adapter);
const userDatabase = low(new FileSync("database/users.json"));
const deviceDatabase = low(new FileSync("database/devices.json"));

// Set some defaults
credDatabase.defaults({ credentials: [] }).write();
userDatabase.defaults({ users: [] }).write();
deviceDatabase.defaults({ devices: [] }).write();

function cleanAAGUID(aaguid) {
  var cleanAaguid = aaguid
    .replace(/-/g, "")
    .replace(/ /g, "")
    .toLowerCase()
    .trim();
  return (
    cleanAaguid.slice(0, 8) +
    "-" +
    cleanAaguid.slice(8, 12) +
    "-" +
    cleanAaguid.slice(12, 16) +
    "-" +
    cleanAaguid.slice(16, 20) +
    "-" +
    cleanAaguid.slice(20)
  );
}

function isAAGUIDValid(aaguid) {
  var cleanAAGUID = aaguid
    .replace(/-/g, "")
    .replace(/ /g, "")
    .toLowerCase()
    .trim();
  return cleanAAGUID.length == 32;
}

function getDevice(aaguid) {
  //return deviceDatabase.get('devices').find({ aaguid: aaguid.replace(/-/g,"") }).value();
  return deviceDatabase.get("devices").find({ aaguid: aaguid }).value();
}

function getDevices() {
  return deviceDatabase.get("devices").filter({ display: true }).value();
}

function addDevice(aaguid, name, image) {
  aaguid = cleanAAGUID(aaguid);

  device = deviceDatabase.get("devices").find({ aaguid: aaguid }).value();

  if (device === undefined)
    deviceDatabase
      .get("devices")
      .push({ aaguid: aaguid, name: name, image: image, display: true })
      .value();
  else
    deviceDatabase
      .get("devices")
      .find({ aaguid: aaguid })
      .assign({ name: name, image: image })
      .value();
  deviceDatabase.write();
}

function deleteDevice(aaguid) {
  deviceDatabase.get("devices").remove({ aaguid: aaguid }).write();
  deviceDatabase.write();
}

function createUser(id, name, displayName, isAdmin = false) {
  // Check if user  already exists
  let user = getUser(id);
  if (user != null) return user;
  let data = { id: id, name: name, displayName: displayName, isAdmin: isAdmin };
  userDatabase.get("users").push(data).write();
  return data;
}

function checkAdminPassword(name, password) {
  let user = { ...userDatabase.get("users").find({ name: name }).value() };
  if (user == null) return false;
  if (!user.isAdmin) return false;
  if (user.password == password) return true;
  return false;
}

function getUser(id) {
  let user = userDatabase.get("users").find({ id: id }).value();
  if (user == undefined) return null;

  delete user["password"];
  return user;
}

function getUserByName(name) {
  let user = userDatabase.get("users").find({ name: name }).value();
  if (user == undefined) return null;

  delete user["password"];
  return user;
}

function getUsers() {
  let users = userDatabase.get("users").value();
  if (users == undefined) return null;

  return users;
}

function getCredential(id) {
  return credDatabase.get("credentials").find({ credId: id }).value();
}

function deleteNonAdminUsers() {
  users = userDatabase.get("users").filter({ isAdmin: false }).value();
  let count = users.length;
  users.forEach((user) => {
    userDatabase.get("users").remove({ id: user.id }).write();
    credDatabase.get("credentials").remove({ userId: user.id }).write();
  });
  return count;
}

function getCredentials(userId) {
  let credentials = credDatabase
    .get("credentials")
    .filter({ userId: userId })
    .value();

  // Clone the array to not modify the database
  let cloneCredentials = JSON.parse(JSON.stringify(credentials));
  cloneCredentials.forEach((credential) => {
    let device = getDevice(credential.aaguid);
    if (device == null) device = getDevice("Unknown");
    credential.deviceName = device.name;
    credential.deviceImage = device.image;
  });
  return cloneCredentials;
}

function getActiveCredentials(userId) {
  let credentials = credDatabase
    .get("credentials")
    .filter({ userId: userId, active: true })
    .value();

  return credentials;

  // Clone the array to not modify the database
  let cloneCredentials = JSON.parse(JSON.stringify(credentials));
  cloneCredentials.forEach((credential) => {
    let device = getDevice(credential.aaguid);
    if (device == null) device = getDevice("Unknown");
    credential.deviceName = device.name;
    credential.deviceImage = device.image;
  });
  return cloneCredentials;
}

function createCredential(user, data) {
  credDatabase
    .get("credentials")
    .push({
      credId: data.credID,
      userId: user.id,
      aaguid: data.aaguid,
      cert: data.cert,
      counter: data.counter,
      active: true,
      fmt: data.fmt,
      publicKey: data.publicKey,
    })
    .write();
  return data;
}

function updateCredentialStatus(credId, active) {
  let credential = getCredential(credId);
  credential.active = active;
  credDatabase.write();
}

function save() {
  credDatabase.write();
  userDatabase.write();
}

module.exports = {
  getUserByName,
  getUser,
  getUsers,
  getCredential,
  getCredentials,
  getDevices,
  addDevice,
  deleteDevice,
  createUser,
  createCredential,
  save,
  isAAGUIDValid,
  cleanAAGUID,
  deleteNonAdminUsers,
  checkAdminPassword,
  updateCredentialStatus,
  getActiveCredentials,
};
