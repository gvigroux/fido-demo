const crypto    = require('crypto');
const base64url = require('base64url');
const cbor      = require('cbor');
const fs        = require('fs');
const { Certificate } = require('@fidm/x509');


let userVerificationDefault = "preferred"; //userVerification - can be set to "required", "preferred", "discouraged". More in WebAuthn specification. Default set to "preferred"


/**
 * U2F Presence constant
 */
let U2F_USER_PRESENTED = 0x01;

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
let verifySignature = (signature, data, publicKey) => {
    return crypto.createVerify('SHA256')
        .update(data)
        .verify(publicKey, signature);
}


/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
let randomBase64URLBuffer = (len) => {
    len = len || 32;
    let buff = crypto.randomBytes(len);
    return base64url(buff);
}

/**
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
let generateServerMakeCredRequest = (userVerification, requireResidentKey, id, username, displayName) => {
    if( userVerification == null) userVerification = userVerificationDefault;
    return {
        attestation: 'direct',
        authenticatorSelection : {
            requireResidentKey: requireResidentKey,
            userVerification: userVerification
        },
        challenge: randomBase64URLBuffer(32),
        pubKeyCredParams: [
            {
                type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
            }
        ],
        rp: {
            //id: "fido.demo.gemalto.com",
            name: "Thales FIDO Demo"
        },
        timeout: 90000,
        user: {
            id: id,
            name: username,
            displayName: displayName
        }
    }
}

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
let generateServerGetAssertion = (userVerification, authenticators) => {
    if( userVerification == null) userVerification = userVerificationDefault;

    let allowCredentials = [];
    for(let authr of authenticators) {
        allowCredentials.push({
              type: 'public-key',
              id: authr.credID
              //,transports: ['usb', 'nfc', 'ble']
        })
    }
    return {
        challenge: randomBase64URLBuffer(32)
        ,timeout: 60000
        ,allowCredentials: allowCredentials
        ,userVerification: userVerification
    }
}


/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
let hash = (data) => {
    return crypto.createHash('SHA256').update(data).digest();
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
let COSEECDHAtoPKCS = (COSEPublicKey) => {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
    let tag = Buffer.from([0x04]);
    let x   = coseStruct.get(-2);
    let y   = coseStruct.get(-3);

    return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
let ASN1toPEM = (pkBuffer) => {
    if (!Buffer.isBuffer(pkBuffer))
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

    let type;
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */
        
        pkBuffer = Buffer.concat([
            new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            pkBuffer
        ]);

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = pkBuffer.toString('base64');
    return formatPEM(b64cert, type);

    /*
    let PEMKey = '';
    for(let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMKey += b64cert.substr(start, 64) + '\n';
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;
    
    return PEMKey
    */
}

let formatPEM = (b64cert, type = "CERTIFICATE") => {
    let PEMKey = '';
    for(let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;
        PEMKey += b64cert.substr(start, 64) + '\n';
    }
    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;
    return PEMKey;
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseMakeCredAuthData = (buffer) => {
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flags         = flagsBuf[0];
    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);
    let aaguid        = buffer.slice(0, 16);          buffer = buffer.slice(16);
    let credIDLenBuf  = buffer.slice(0, 2);           buffer = buffer.slice(2);
    let credIDLen     = credIDLenBuf.readUInt16BE(0);
    let credID        = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
    let COSEPublicKey = buffer;

    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}
}

let verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
    console.log("verifyAuthenticatorAttestationResponse");
    let attestationBuffer    = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    let attestationObject    = cbor.decodeAllSync(attestationBuffer)[0];

    /*
    let details = " type: self";
    let attestationType = "self";
    if( ctapMakeCredResp.attStmt !== undefined && ctapMakeCredResp.attStmt.x5c !== undefined) {
        details += " type: AttCA with X5C length: " + ctapMakeCredResp.attStmt.x5c.length;
        attestationType = "AttCA";
    }
    if( ctapMakeCredResp.attStmt !== undefined && ctapMakeCredResp.attStmt.ecdaaKeyId !== undefined) {
        details += " type: ECDAA";
        attestationType = "ECDAA";
    }
    console.log("Attestation received: " + ctapMakeCredResp.fmt + " " + details);
    */

    console.log("Attestation received: " + attestationObject.fmt);

    let authDataBuffer = attestationObject.authData;
    attestationObject.authData = parseMakeCredAuthData(authDataBuffer);
    let clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))

    let response = {'verified': false, 'fmt': attestationObject.fmt, 'message': "" , 'log' : '', attestationObject: attestationObject };

    if(attestationObject.fmt === 'fido-u2f') {

        response = u2fAttestation(attestationObject, clientDataHash);

        /*
        if(!(attestationObject.authData.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let reservedByte    = Buffer.from([0x00]);
        let publicKey       = COSEECDHAtoPKCS(attestationObject.authData.COSEPublicKey)
        let signatureBase   = Buffer.concat([reservedByte, attestationObject.authData.rpIdHash, clientDataHash, attestationObject.authData.credID, publicKey]);

        let PEMCertificate = ASN1toPEM(attestationObject.attStmt.x5c[0]);
        let signature      = attestationObject.attStmt.sig;

        
        // console.log(PEMCertificate);
        // console.log(ctapMakeCredResp.attStmt.sig.length);
        // console.log(signature.toString("hex"));
        // console.log(hash(signature).toString("hex"));   
        // console.log(ctapMakeCredResp.attStmt.sig.length - 70);
        // let signature = Buffer.allocUnsafe(70);
        // ctapMakeCredResp.attStmt.sig.copy(signature,0, ctapMakeCredResp.attStmt.sig.length - 70)
        

        
        let maxTrailingZero = 0;
        for(let i = 0; i < signature.length ; i++) {
            if( signature.readInt8(i) === 0)
                maxTrailingZero = i + 1;
            else 
                break;
        }

        if( maxTrailingZero > 0) {
            console.log("WARNING - I modifiy the length");
            signature = signature.slice(maxTrailingZero);
        }


        console.log(signature.length);
        console.log(signature);

        
        // console.log(signature);
        // console.log(signatureBase);
        // console.log(base64url.decode(webAuthnResponse.response.clientDataJSON));
        // console.log(hash(signatureBase).toString("hex"));

        // Save cert
        let filename = saveCertificate(PEMCertificate);


        response.verified = verifySignature(signature, signatureBase, PEMCertificate);
        if( !response.verified ) {
            console.log("Invalid Signature");
        }
        
        // Try to detect device
        let cert = Certificate.fromPEM(PEMCertificate);
        let aaguid = '';

        // The certificate should contain the product ID in this OID
        for(let i = 0 ; i < cert.extensions.length ; i ++) {
            if( cert.extensions[i].oid === "1.3.6.1.4.1.45724.1.1.4") {
                aaguid = cert.extensions[i].value.slice(2);
                break;
            }   
        }

        // Try to get the first OID
        if( aaguid.length <= 0 ) {
            for(let i = 0 ; i < cert.extensions.length ; i ++) {
                // Transport OID "1.3.6.1.4.1.45724.2.1.1"
                if( cert.extensions[i].oid.indexOf("1.3.6.1.4.1.") == 0 && cert.extensions[i].oid.indexOf("1.3.6.1.4.1.45724.2.1.1") !== 0 ) {
                    aaguid = cert.extensions[i].value;
                    break;
                }    
            }
        }


        if(response.verified) {
            console.log("Attestation Verified");
            response.attestationObject.attStmt.sig = response.attestationObject.attStmt.sig.toString('base64');
            response.authrInfo = {
                fmt: 'fido-u2f',
                aaguid: convertAAGUID(aaguid),
                publicKey: base64url.encode(publicKey),
                counter: attestationObject.authData.counter,
                credID: base64url.encode(attestationObject.authData.credID),
                cert: filename
            }
        }
        else
            console.log("Attestation NOT Verified");
            */
    } 
    else if (attestationObject.fmt === 'packed' && attestationObject.attStmt.x5c !== undefined) {        
        response = packedAttestation(attestationObject, clientDataHash, authDataBuffer);

/*
        // https://www.w3.org/TR/webauthn/#packed-attestation
        
        let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

        let clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let publicKey       = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)

        // Step 1 - Verify that sig is a valid signature
        let signatureBase   = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);
        let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
        let signature      = ctapMakeCredResp.attStmt.sig;
        response.verified = verifySignature(signature, signatureBase, PEMCertificate);
        if( !response.verified ) response.message = "Invalid Signature";

        // Save cert
        let filename = "cert/" + crypto.createHash('md5').update(authrDataStruct.credID).digest("hex") + ".crt";
        fs.writeFileSync( "static/" + filename, PEMCertificate);

        // Step 2 - ???

        // Step 3 - if OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) 
        //          verify that the value of this extension matches the aaguid in authenticatorData.
        
        // DEBUG: PEMCertificate = fs.readFileSync("cert/card.crt");
        //PEMCertificate = fs.readFileSync("cert/ctap_fpvcFk2ZxU8RsZDihqbO23ARBn4sKK_Y0akjna8tAhIt2vfCWgw29_F5KrWFaAb4-PEjYjW_lqPMgccDmwrEVu6CaEQsEaektvPLiig.crt");

        let checkAAGUID = true;
        if( checkAAGUID )
        {
            let cert = Certificate.fromPEM(PEMCertificate);
            for(let i = 0 ; i < cert.extensions.length ; i ++) {
                if( cert.extensions[i].oid === "1.3.6.1.4.1.45724.1.1.4") {

                    let certValue = Buffer.from(cert.extensions[i].value, 2);
                    response.verified = certValue.equals(authrDataStruct.aaguid);
                    if( !response.verified ) {   
                        response.message    = "Invalid AAGUID";
                        response.log        = "Invalid AAGUID [" + JSON.stringify(authrDataStruct.aaguid) + "] [" + JSON.stringify(certValue) + "]";
                        console.log(response.log);
                    }
                    break;
                }
            }
        }


        if(response.verified) {
            response.authrInfo = {
                fmt: 'packed',
                aaguid: authrDataStruct.aaguid.toString('hex'),
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID),
                cert: filename
            }
        }
        */
    }
    /*
    else if (ctapMakeCredResp.fmt === "android-key")
    {
        let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

        let clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let publicKey       = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)        

        // Step 1 - Verify that sig is a valid signature
        let signatureBase   = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);
        let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
        let signature      = ctapMakeCredResp.attStmt.sig;
        response.verified = verifySignature(signature, signatureBase, PEMCertificate);
        if( !response.verified ) response.message = "Invalid Signature";

        // Save cert
        let filename = "cert/" + crypto.createHash('md5').update(authrDataStruct.credID).digest("hex") + ".crt";
        fs.writeFileSync( "static/" + filename, PEMCertificate);

        if(response.verified) {
            response.authrInfo = {
                fmt: ctapMakeCredResp.fmt,
                aaguid: authrDataStruct.aaguid.toString('hex'),
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID),
                cert: filename
            }
        }
    }
    */
    else if (ctapMakeCredResp.fmt === "android-safetynet")
    {
        response = androidSafetynetAttestation(attestationObject, clientDataHash);

        /*
        let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

        let clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let publicKey       = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);

        let ver = ctapMakeCredResp.attStmt.ver;
        let response = ctapMakeCredResp.attStmt.response.toString("utf-8");
        
        console.log(ver);

        let jwsArray = response.split(".");
        if( jwsArray.length )

        let nonce   = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]).toString('base64');
        */


        /*
        // Step 1 - Verify that sig is a valid signature
        let signatureBase   = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);
        let PEMCertificate  = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
        let signature       = ctapMakeCredResp.attStmt.sig;
        response.verified   = verifySignature(signature, signatureBase, PEMCertificate);
        if( !response.verified ) response.message = "Invalid Signature";

        // Save cert
        let filename = "cert/" + crypto.createHash('md5').update(authrDataStruct.credID).digest("hex") + ".crt";
        fs.writeFileSync( "static/" + filename, PEMCertificate);


        if(response.verified) {
            response.authrInfo = {
                fmt: ctapMakeCredResp.fmt,
                aaguid: authrDataStruct.aaguid.toString('hex'),
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID),
                cert: filename
            }
        }
        */
    }
    else
    {                
        response.authrInfo = {
            fmt: attestationObject.fmt,            
        }
        response.message = 'Unsupported attestation [' + attestationObject.fmt + "]"; 
    }
    
    // Format attestationObject for logs
    if( response.verified == true)
    {
        attestationLog = {attStmt: {x5c: []}, authData: {credentialData: {}}};

        // Prepare "attStmt"
        attestationLog.attStmt.sig = attestationObject.attStmt.sig.toString('base64');
        attestationObject.attStmt.x5c.forEach(x5c => attestationLog.attStmt.x5c.push(x5c.toString('base64')));

        // Prepare "credentialData"
        attestationLog.authData.credentialData.aaguid           = attestationObject.authData.aaguid.toString('base64');
        attestationLog.authData.credentialData.credentialId     = attestationObject.authData.credID.toString('base64');
        attestationLog.authData.credentialData.rpIdHash         = attestationObject.authData.rpIdHash.toString('base64');
        attestationLog.authData.credentialData.signatureCounter = attestationObject.authData.signatureCounter;

        // Prepare "fmt"
        attestationLog.fmt = attestationObject.fmt;
        
        // Assign the log object
        response.attestationObject = attestationLog;

        /*
              "credentialData": {
        "aaguid": "AAAAAAAAAAAAAAAAAAAAAA==",
        "credentialId": "aRaHCZ8z63X946K6WFwE5+Naqcc0P3mw46/23s4dHMc5xmjuAmVav4wiAl1LjHlimW2ABKYFl4govGNffdNrktNiU6xr8qNSCh+mqP5MJI6DRq4Z65o5QkABkG1ElcZXsO83ACCFL9JAeRj9X9ufqG4qC31v91Sjk9v2gunfnrcda6fRtNBA9yn9/ONoxbzuXg5LeGV7MRM6NNUwrCREYQ==",
        "publicKey": {
          "1": 2,
          "3": -7,
          "-1": 1,
          "-2": "ia56X+doqE2bb+rmkT5gM6jQZe2zfb6xAHR55uM6Lyc=",
          "-3": "fWnMFdHhu9An/oguPJLHTarRHdFCjGTEiO9lOW8hJmE="
        }
      },
      "flags": {
        "AT": true,
        "ED": false,
        "UP": true,
        "UV": false,
        "value": 65
      },
      "rpIdHash": "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7c=",
      "signatureCounter": 0   },
    "fmt": "fido-u2f"
      */

    }

    return response
}

/**
 * save cert
 * @param  {Buffer} data    - certificate Data
 * @return {String}         - filename
 */

let saveCertificate = (data) => {
    let filename = "cert/" + crypto.createHash('md5').update(data).digest("hex") + ".crt";
    fs.writeFileSync( "static/" + filename, data);
    return filename;
}


function u2fAttestation(attestationObject, clientDataHash) {

    if(!(attestationObject.authData.flags & U2F_USER_PRESENTED)) {        
        console.log("User presented FLAG");
        return {verified: false, message: "User presented FLAG"};
    }

    let reservedByte    = Buffer.from([0x00]);
    let publicKey       = COSEECDHAtoPKCS(attestationObject.authData.COSEPublicKey)
    let signatureBase   = Buffer.concat([reservedByte, attestationObject.authData.rpIdHash, clientDataHash, attestationObject.authData.credID, publicKey]);

    let PEMCertificate = ASN1toPEM(attestationObject.attStmt.x5c[0]);
    let signature      = attestationObject.attStmt.sig;

    let maxTrailingZero = 0;
    for(let i = 0; i < signature.length ; i++) {
        if( signature.readInt8(i) === 0)
            maxTrailingZero = i + 1;
        else 
            break;
    }
    if( maxTrailingZero > 0) {
        console.log("WARNING - I modify the length");
        signature = signature.slice(maxTrailingZero);
    }

    // Save cert
    let filename = saveCertificate(PEMCertificate);

    if( !verifySignature(signature, signatureBase, PEMCertificate) ) {
        console.log("Invalid Signature");
        return {verified: false, message: "Invalid Signature"};
    }

    // Try to detect device
    let cert    = Certificate.fromPEM(PEMCertificate);
    let aaguid  = '';

    // The certificate should contain the product ID in this OID
    for(let i = 0 ; i < cert.extensions.length ; i ++) {
        if( cert.extensions[i].oid === "1.3.6.1.4.1.45724.1.1.4") {
            aaguid = cert.extensions[i].value.slice(2);
            break;
        }   
    }

    // Try to get the first OID
    if( aaguid.length <= 0 ) {
        for(let i = 0 ; i < cert.extensions.length ; i ++) {
            // Transport OID "1.3.6.1.4.1.45724.2.1.1"
            if( cert.extensions[i].oid.indexOf("1.3.6.1.4.1.") == 0 && cert.extensions[i].oid.indexOf("1.3.6.1.4.1.45724.2.1.1") !== 0 ) {
                aaguid = cert.extensions[i].value;
                break;
            }    
        }
    }


    console.log("U2F Attestation Verified");

    let authrInfo = {
        fmt: 'fido-u2f',
        aaguid: convertAAGUID(aaguid),
        publicKey: base64url.encode(publicKey),
        counter: attestationObject.authData.counter,
        credID: base64url.encode(attestationObject.authData.credID),
        cert: filename };


    return {verified: true, authrInfo: authrInfo, message: "OK", attestationObject: attestationObject};
}





/**
 * Validate packed attestation
 * @param  {Buffer} attestationObject   - ctapMakeCred buffer
 * @param  {String} clientDataHash      - hash
 * @param  {String} authDataBuffer      - Original buffer
 * @return {Object}                     - parsed authenticatorData struct
 */
let packedAttestation = (attestationObject, clientDataHash, authDataBuffer) => {

    // https://www.w3.org/TR/webauthn/#packed-attestation
    
    let publicKey       = COSEECDHAtoPKCS(attestationObject.authData.COSEPublicKey);

    // Step 1 - Verify that sig is a valid signature
    let signatureBase  = Buffer.concat([authDataBuffer, clientDataHash]);
    let PEMCertificate = ASN1toPEM(attestationObject.attStmt.x5c[0]);
    let signature      = attestationObject.attStmt.sig;
    if( !verifySignature(signature, signatureBase, PEMCertificate) ) 
    {
        console.log("invalid Signature");
        return {verified: false, message: "invalid Signature"};
    }

    // Save cert
    let filename = saveCertificate(PEMCertificate);

    // Step 2 - ???

    // Step 3 - if OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) 
    //          verify that the value of this extension matches the aaguid in authenticatorData.
   
    // DEBUG: PEMCertificate = fs.readFileSync("cert/card.crt");
    //PEMCertificate = fs.readFileSync("cert/ctap_fpvcFk2ZxU8RsZDihqbO23ARBn4sKK_Y0akjna8tAhIt2vfCWgw29_F5KrWFaAb4-PEjYjW_lqPMgccDmwrEVu6CaEQsEaektvPLiig.crt");

    let checkAAGUID = true;
    if( checkAAGUID )
    {
        let cert = Certificate.fromPEM(PEMCertificate);
        for(let i = 0 ; i < cert.extensions.length ; i ++) {
            if( cert.extensions[i].oid === "1.3.6.1.4.1.45724.1.1.4") {

                let certValue = cert.extensions[i].value.slice(2);
                if( !certValue.equals(attestationObject.authData.aaguid)) {
                    let log = "Invalid AAGUID [" + JSON.stringify(attestationObject.authData.aaguid) + "] [" + JSON.stringify(certValue) + "]";
                    console.log(log);
                    return {verified: false, message: "invalid AAGUID", log: log};
                }
                break;
            }
        }
    }

    let authrInfo = {
            fmt: attestationObject.fmt,
            aaguid: convertAAGUID(attestationObject.authData.aaguid),
            publicKey: base64url.encode(publicKey),
            counter: attestationObject.authData.counter,
            credID: base64url.encode(attestationObject.authData.credID),
            cert: filename
        };    
        
    console.log("Attestation is valid");
    return {verified: true, authrInfo: authrInfo, message: "OK", attestationObject: attestationObject};
}


let convertAAGUID  = (byteArray) => {
    if( byteArray.length == 18 )
        byteArray = byteArray.slice(2);
    let aaguid = byteArray.toString('hex').toLowerCase();
    aaguid = aaguid.slice(0,8) + '-' + aaguid.slice(8);
    aaguid = aaguid.slice(0,13) + '-' + aaguid.slice(13);
    aaguid = aaguid.slice(0,18) + '-' + aaguid.slice(18);
    aaguid = aaguid.slice(0,23) + '-' + aaguid.slice(23);
    return aaguid;
}



/**
 * Validate android-safetynet attestation
 * @param  {Buffer} attestationObject    - ctapMakeCred buffer
 * @param  {String} clientDataHash      - hash
 * @return {Object}                     - parsed authenticatorData struct
 */
let androidSafetynetAttestation = (attestationObject, clientDataHash) => {

    //let authrDataStruct = parseMakeCredAuthData(attestationObject.authData);
    let publicKey       = COSEECDHAtoPKCS(attestationObject.authData.COSEPublicKey);

    let ver      = attestationObject.attStmt.ver;
    let response = attestationObject.attStmt.response.toString("utf-8");
    
    let jwsArray = response.split(".");
    if( jwsArray.length <= 2 )
        return {verified: false, message: "invalid JWS attestation"}

    // STEP 1 - Get certificate
    let attestation = JSON.parse(base64url.decode(jwsArray[0]));
    let PEMCertificate  = formatPEM(attestation.x5c[0]);

    // Save cert    
    let filename = saveCertificate(PEMCertificate);

    // Compare hostname
    let cert = Certificate.fromPEM(PEMCertificate);
    let hostnameIsValid = false;
    for(let i = 0 ; i < cert.subject.attributes.length ; i++) {
        if(( cert.subject.attributes[i].shortName === 'CN' ) && (cert.subject.attributes[i].value === 'attest.android.com'))
            hostnameIsValid = true;
    }
    if( !hostnameIsValid ) 
        return {verified: false, message: "invalid Hostname"}
    

    // STEP 2 - Verify nonce
    let jws     = JSON.parse(base64url.decode(jwsArray[1]));
    let nonce   = crypto.createHash('sha256').update(Buffer.concat([attestationObject.authData, clientDataHash])).digest().toString('base64'); 

    if( nonce != jws.nonce)
        return {verified: false, message: "invalid nonce"}

    // STEP 2 - Verify ctsProfileMatch = true
    if( jws.ctsProfileMatch !== true)
        return {verified: false, message: "invalid ctsProfileMatch"}


    let authrInfo = {
            fmt: attestationObject.fmt,
            aaguid: attestationObject.authData.aaguid.toString('hex'),
            publicKey: base64url.encode(publicKey),
            counter: attestationObject.authData.counter,
            credID: base64url.encode(attestationObject.authData.credID),
            cert: filename
        };
    
        
    console.log("Attestation is valid");
    return {verified: true, authrInfo: authrInfo, message: "OK", attestationObject: attestationObject};
}







/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
let findAuthr = (credID, authenticators) => {
    for(let authr of authenticators) {
        if(authr.credID === credID)
            return authr
    }
    throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseGetAssertAuthData = (buffer) => {
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flags         = flagsBuf[0];
    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);

    return {rpIdHash, flagsBuf, flags, counter, counterBuf}
}

let verifyAuthenticatorAssertionResponse = (webAuthnResponse, authenticators) => {
    let authr = findAuthr(webAuthnResponse.id, authenticators);
    let authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData);

    let response = {'verified': false};

    //*********************************************** */
    // Generic check

    let authrDataStruct = parseGetAssertAuthData(authenticatorData);
    let clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));

    if(!(authrDataStruct.flags & U2F_USER_PRESENTED))
    throw new Error('User was NOT presented durring authentication!');

    let publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
    let signature = base64url.toBuffer(webAuthnResponse.response.signature);
    let signatureBase    = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);

    response.verified = verifySignature(signature, signatureBase, publicKey);
    if( !response.verified ) response.message = "Invalid Signature";

    if(response.verified) {
        if(response.counter <= authr.counter)
            throw new Error('Authr counter did not increase!');
        authr.counter = authrDataStruct.counter
    }






    /*
    if(authr.fmt === 'fido-u2f') {
        let authrDataStruct  = parseGetAssertAuthData(authenticatorData);

        if(!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let clientDataHash   = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let signatureBase    = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);

        let publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
        let signature = base64url.toBuffer(webAuthnResponse.response.signature);

        response.verified = verifySignature(signature, signatureBase, publicKey)

        if(response.verified) {
            if(response.counter <= authr.counter)
                throw new Error('Authr counter did not increase!');

            authr.counter = authrDataStruct.counter
        }
    }
    else if(authr.fmt === 'packed') {    
        let authrDataStruct = parseGetAssertAuthData(authenticatorData);

        let clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
        let signature = base64url.toBuffer(webAuthnResponse.response.signature);
        let signatureBase    = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);

        // Step 1 - Verify that sig is a valid signature
        response.verified = verifySignature(signature, signatureBase, publicKey);
        if( !response.verified ) response.message = "Invalid Signature";

        if(response.verified) {
            if(response.counter <= authr.counter)
                throw new Error('Authr counter did not increase!');
            authr.counter = authrDataStruct.counter
        }
    }
    else if(authr.fmt === 'android-safetynet') {    
        console.log("login with: " + authr.fmt); 
        let authrDataStruct = parseGetAssertAuthData(authenticatorData);
        let clientDataHash  = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));

        
        let publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
        let signature = base64url.toBuffer(webAuthnResponse.response.signature);
        let signatureBase    = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);

        console.log(publicKey);
        console.log(signature);
        console.log(signatureBase);

        // Step 1 - Verify that sig is a valid signature
        response.verified = verifySignature(signature, signatureBase, publicKey);
        if( !response.verified ) response.message = "Invalid Signature";

        console.log(authr);
        console.log(authrDataStruct);
        console.log(clientDataHash);

        //response.verified = true;
        if(response.verified) {
            if(response.counter <= authr.counter)
                throw new Error('Authr counter did not increase!');
            authr.counter = authrDataStruct.counter
        }
    }*/
    

    return response;
}

module.exports = {
    randomBase64URLBuffer,
    generateServerMakeCredRequest,
    generateServerGetAssertion,
    verifyAuthenticatorAttestationResponse,
    verifyAuthenticatorAssertionResponse
}