const express = require("express");
const handlebars = require("express-handlebars");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const session = require("express-session");
const path = require("path");
const saml = require('samlify');
const { readFileSync } = require('fs');

saml.setSchemaValidator({
  validate: (response) => {
    /* implment your own or always returns a resolved promise to skip */
    return Promise.resolve('skipped');
  }
});

const app = express();

passport.use(
  new LocalStrategy(function verify(username, password, cb) {
    console.log("login success with user", { username, password });
    return cb(null, {username, password});
  })
);

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, user);
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

app.use(express.urlencoded({ extended: false }));
app.engine("handlebars", handlebars.engine());
app.set("view engine", "handlebars");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

function loggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.redirect("/login");
  }
}

app.get("/", loggedIn, (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post(
  "/login/password",
  passport.authenticate("local",{
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

const idp = saml.IdentityProvider({
  metadata: readFileSync(__dirname + "/../metadata/idp-metadata.xml"),
  
});

const sp = saml.ServiceProvider({
  metadata: readFileSync(__dirname + '/../metadata/sp-metadata.xml')
});

app.post("/login/sso", async (req, res) => {
  // create saml request
  const  { context } = sp.createLoginRequest(idp, saml.Constants.wording.binding.redirect);
  // redirect to idp login
  res.redirect(context);
});

app.get('/acs', async (req, res) => {
  try {
      const parseResult = await sp.parseLoginResponse(idp, "post", { body: {
        SAMLResponse: req.query.SAMLResponse,
      }});

      console.log(parseResult.extract);
      // handle login
      req.logIn({
        username: 'test',
        password: 'test',
      }, function(err) {
        if (err) { return next(err); }
        return res.redirect('/');
      });
  } catch (e) {
      console.log(e)
      res.status(500).send()
  }
});

app.listen(3002, () => {
  console.log("Service provider listening on port 3002");
});

