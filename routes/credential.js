const express = require("express");
const router = express.Router();
const database = require("../class/database");

router.post("/status", (request, response) => {
  if (!request.body) return response.json({ message: "Invalid request" });

  if (!("credId" in request.body))
    return response.json({ invalidField: "credId" });
  if (!("active" in request.body))
    return response.json({ invalidField: "active" });

  // Update status
  database.updateCredentialStatus(request.body.credId, request.body.active);

  return response.json({ success: true });
});

module.exports = router;
