function makeCredential() {
  let name = $("#name").val();
  let displayName = $("#displayName").val();
  let userVerification = $("#userVerification").val();
  let discoverableCredential = $("#discoverableCredential").val();
  let authenticatorAttachment = $("#authenticatorAttachment").val();
  let useExtensionUcm = $("#useExtensionUcm").val();
  let useExtensionCredProps = $("#useExtensionCredProps").val();
  let excludeCredentials = $("#excludeCredentials").val();

  postWebAuthN("getMakeCredentialsChallenge", {
    name,
    displayName,
    userVerification,
    discoverableCredential,
    authenticatorAttachment,
    useExtensionUcm,
    useExtensionCredProps,
    excludeCredentials,
  })
    .then((publicKey) => {
      // Receive 'credentials create' options
      //let publicKey = preformatMakeCredReq(response);

      publicKey.user.id = base64url.decode(publicKey.user.id);
      publicKey.challenge = base64url.decode(publicKey.challenge);

      if (Array.isArray(publicKey.excludeCredentials)) {
        publicKey.excludeCredentials.forEach((credential) => {
          credential.id = base64url.decode(credential.id);
        });
      }

      console.log(publicKey);
      return navigator.credentials.create({ publicKey });
    })
    .then((response) => {
      let makeCredResponse = publicKeyCredentialToJSON(response);
      return postWebAuthN("verifyAttestation", makeCredResponse);
    })
    .then((response) => {
      console.log(response.signatureDetails);
      if (response.message !== undefined)
        return $("#error").html(response.message);
      // Success: redirect to main page
      document.location.href = "main";
    })
    .catch((error) => {
      console.log(error);
      /*
      if (error instanceof DOMException)
        return $("#error").html("The operation either timed out or was cancelled");                      
      $("#error").html(error.message);
      */
    });
}
