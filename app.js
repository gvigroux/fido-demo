const express = require("express");
const bodyParser = require("body-parser");
//const cookieSession = require('cookie-session');
//const cookieParser  = require('cookie-parser');
const session = require("express-session");

const urllib = require("url");
const path = require("path");
const crypto = require("crypto");
const config = require("./config.json");
const defaultroutes = require("./routes/default");
const webuathnauth = require("./routes/webauthn.js");
const credential = require("./routes/credential.js");
const admin = require("./routes/admin.js");
const mds = require("./routes/mds.js");

const app = express();

// view engine setup
app.engine("pug", require("pug").__express);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");

app.use(bodyParser.json());

/* ----- session ----- */
/*app.use(cookieSession({
  name: 'session',
  keys: [crypto.randomBytes(32).toString('hex')],
  // Cookie Options
  maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))
app.use(cookieParser())
*/

app.use(
  session({
    secret: crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: true,
  })
);

app.use("/", defaultroutes);
app.use("/webauthn", webuathnauth);
app.use("/admin", admin);
app.use("/mds", mds);
app.use("/credential", credential);

/* ----- serve static ----- */
app.use(express.static(path.join(__dirname, "static")));
app.use(express.static(path.join(__dirname, "bower_components")));

const port = config.port || 3000;
app.listen(port);
console.log(`Started app on port ${port}`);

module.exports = app;
