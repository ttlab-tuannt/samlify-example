const express = require("express");
const saml = require('samlify');
const handlebars = require("express-handlebars");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const session = require("express-session");
const path = require("path");

const { addMinutes } = require('date-fns')
const { readFileSync } = require('fs');
const { randomUUID } = require('crypto');

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

const generateRequestID = () => {
    return '_' + randomUUID()
}

const createTemplateCallback = (idp, sp, email) => template => {
    const assertionConsumerServiceUrl = sp.entityMeta.getAssertionConsumerService(saml.Constants.wording.binding.post)

    const nameIDFormat = idp.entitySetting.nameIDFormat
    const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat

    const id = generateRequestID()
    const now = new Date()
    const fiveMinutesLater = addMinutes(now, 5)

    const tagValues = {
        ID: id,
        AssertionID: generateRequestID(),
        Destination: assertionConsumerServiceUrl,
        Audience: sp.entityMeta.getEntityID(),
        EntityID: sp.entityMeta.getEntityID(),
        SubjectRecipient: assertionConsumerServiceUrl,
        Issuer: idp.entityMeta.getEntityID(),
        IssueInstant: now.toISOString(),
        AssertionConsumerServiceURL: assertionConsumerServiceUrl,
        StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
        ConditionsNotBefore: now.toISOString(),
        ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
        SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
        NameIDFormat: selectedNameIDFormat,
        NameID: email,
        InResponseTo: 'null',
        AuthnStatement: '',
        attrFirstName: 'Tuan',
        attrLastName: 'Nguyen',
        attrEmail: email
    }

    return {
        id,
        context: saml.SamlLib.replaceTagsByValue(template, tagValues)
    }
}

const sp = saml.ServiceProvider({
    metadata: readFileSync(__dirname + '/../metadata/sp-metadata.xml')
});


const idp = saml.IdentityProvider({
  metadata: readFileSync(__dirname + "/../metadata/idp-metadata.xml"),
  privateKey: readFileSync(__dirname + "/../keys/idp.pem"),
  privateKeyPass: "secret",
  isAssertionEncrypted: false,
  loginResponseTemplate: {
    context:
      `
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0"
            IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}">
            <saml:Issuer>{Issuer}</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="{StatusCode}" />
            </samlp:Status>
            <saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject>
                    <saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID>
                    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                        <saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}"
                            Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}" />
                    </saml:SubjectConfirmation>
                </saml:Subject><saml:Conditions
                    NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}">
                    <saml:AudienceRestriction>
                        <saml:Audience>{Audience}</saml:Audience>
                    </saml:AudienceRestriction>
                </saml:Conditions>
                {AttributeStatement}</saml:Assertion>
        </samlp:Response>
      `,
    attributes: [
      {
        name: "firstName",
        valueTag: "firstName",
        nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        valueXsiType: "xs:string",
      },
      {
        name: "lastName",
        valueTag: "lastName",
        nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        valueXsiType: "xs:string",
      },
      {
        name: "email",
        valueTag: "email",
        nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:emailAddress",
        valueXsiType: "xs:string",
      },
    ],
  },
});

app.get('/sso/idp/metadata', (req, res) => {
    res.type('application/xml');
    res.send(idp.getMetadata());
});

app.get('/login/sso', async (req, res) => {
    try {
        const requestContent = await idp.parseLoginRequest(sp, saml.Constants.wording.binding.redirect, req);
        console.log(requestContent)
        // const user = { email: 'tuannt@tokyotechlab.com' };
        // const { context, entityEndpoint } = await idp.createLoginResponse(sp, null, saml.Constants.wording.binding.post, user, createTemplateCallback(idp, sp, user.email));

        // res.status(200).send({ samlResponse: context, entityEndpoint })
    } catch (e) {
        console.log(e)
        res.status(500).send()
    }
})

app.listen(3000, () => {
  console.log("IDP listening on port 3000");
});
