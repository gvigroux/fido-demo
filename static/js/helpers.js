/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return {Object}            - JSON encoded publicKeyCredential
 */
var publicKeyCredentialToJSON = (pubKeyCred) => {
  if (pubKeyCred instanceof Array) {
    let arr = [];
    for (let i of pubKeyCred) arr.push(publicKeyCredentialToJSON(i));
    return arr;
  }

  if (pubKeyCred instanceof ArrayBuffer) {
    return base64url.encode(pubKeyCred);
  }

  if (pubKeyCred instanceof Object) {
    let obj = {};
    for (let key in pubKeyCred) {
      obj[key] = publicKeyCredentialToJSON(pubKeyCred[key]);
    }
    return obj;
  }

  return pubKeyCred;
};

/**
 * Decodes arrayBuffer required fields.
 * /
var preformatMakeCredReq = (makeCredReq) => {
  makeCredReq.user.id = base64url.decode(makeCredReq.user.id);
  makeCredReq.challenge = base64url.decode(makeCredReq.challenge);

  if (Array.isArray(makeCredReq.excludeCredentials)) {
     makeCredReq.excludeCredentials.forEach((credential) => {
      credential.id = base64url.decode(credential.id);
     });
  }

  return makeCredReq;
};

/**
 * Decodes arrayBuffer required fields.
 * /
var preformatGetAssertReq = (getAssert) => {
  getAssert.challenge = base64url.decode(getAssert.challenge);

  if (Array.isArray(getAssert.allowCredentials)) {
    getAssert.allowCredentials.forEach((credential) => {
      credential.id = base64url.decode(credential.id);
    });
  }

  return getAssert;
};
*/
