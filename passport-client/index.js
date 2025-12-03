/**
 * LemonLDAP::NG OIDC Client - Express Server with Passport OAuth2
 *
 * Authors: P Vilarem <pvilarem@linagora.com>
 *          X Guimard <xguimard@linagora.com>
 *
 * Licence: GPL V3 https://www.gnu.org/licenses/gpl-3.0.en.html
 */

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const OAuth2Strategy = require("passport-oauth2");
const axios = require("axios");
const crypto = require("crypto");

const app = express();

// Configuration from environment variables
const config = {
  port: process.env.PORT || 9876,
  llngUrl: process.env.LLNG_URL || "https://auth.example.com:19876",
  clientId: process.env.CLIENT_ID || "my-client",
  clientSecret: process.env.CLIENT_SECRET || "",
  redirectUri: process.env.REDIRECT_URI || "http://localhost:9876/callback",
  scope: process.env.SCOPE || "openid email profile",
  sessionSecret:
    process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  pkce: process.env.PKCE === "true",
};

// Session setup
app.use(
  session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  }),
);

app.use(passport.initialize());
app.use(passport.session());

// Fetch OIDC endpoints
async function getOidcEndpoints() {
  try {
    const response = await axios.get(
      `${config.llngUrl}/.well-known/openid-configuration`,
    );
    return {
      authorizationURL: response.data.authorization_endpoint,
      tokenURL: response.data.token_endpoint,
      userInfoURL: response.data.userinfo_endpoint,
      introspectionURL: response.data.introspection_endpoint,
    };
  } catch (error) {
    // Fallback to default endpoints
    return {
      authorizationURL: `${config.llngUrl}/oauth2/authorize`,
      tokenURL: `${config.llngUrl}/oauth2/token`,
      userInfoURL: `${config.llngUrl}/oauth2/userinfo`,
      introspectionURL: `${config.llngUrl}/oauth2/introspect`,
    };
  }
}

// Initialize passport strategy
async function initializePassport() {
  const endpoints = await getOidcEndpoints();

  const strategyOptions = {
    authorizationURL: endpoints.authorizationURL,
    tokenURL: endpoints.tokenURL,
    clientID: config.clientId,
    clientSecret: config.clientSecret,
    callbackURL: config.redirectUri,
    scope: config.scope.split(" "),
    state: true,
  };

  // Add PKCE support if enabled
  if (config.pkce) {
    strategyOptions.pkce = true;
    strategyOptions.state = true;
  }

  const strategy = new OAuth2Strategy(
    strategyOptions,
    async (accessToken, refreshToken, params, profile, done) => {
      try {
        // Fetch user info
        const userInfoResponse = await axios.get(endpoints.userInfoURL, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });

        const user = {
          ...userInfoResponse.data,
          accessToken,
          refreshToken,
          idToken: params.id_token,
        };

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    },
  );

  // Custom authorization params to add prompt=consent for offline_access
  strategy.authorizationParams = function (options) {
    const params = {};
    if (config.scope.includes("offline_access")) {
      params.prompt = "consent";
    }
    return params;
  };

  passport.use("llng", strategy);

  // Store endpoints for later use
  app.locals.endpoints = endpoints;
}

// Serialize/deserialize user
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Routes
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      authenticated: true,
      user: req.user,
    });
  } else {
    res.json({
      authenticated: false,
      loginUrl: "/login",
    });
  }
});

app.get("/login", passport.authenticate("llng"));

app.get(
  "/callback",
  passport.authenticate("llng", { failureRedirect: "/error" }),
  (req, res) => {
    res.redirect("/");
  },
);

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

app.get("/whoami", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  res.json({
    result: req.user.sub || req.user.preferred_username || req.user.name,
  });
});

app.get("/tokens", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  res.json({
    access_token: req.user.accessToken,
    id_token: req.user.idToken,
    refresh_token: req.user.refreshToken,
  });
});

app.get("/access_token", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  res.send(req.user.accessToken);
});

app.get("/id_token", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  res.send(req.user.idToken);
});

app.get("/refresh_token", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  res.send(req.user.refreshToken || "");
});

app.get("/user_info", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  try {
    const response = await axios.get(app.locals.endpoints.userInfoURL, {
      headers: { Authorization: `Bearer ${req.user.accessToken}` },
    });
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/introspection", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  try {
    const auth = Buffer.from(
      `${config.clientId}:${config.clientSecret}`,
    ).toString("base64");
    const response = await axios.post(
      app.locals.endpoints.introspectionURL,
      `token=${req.user.accessToken}`,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${auth}`,
        },
      },
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/oidc_metadata", async (req, res) => {
  try {
    const response = await axios.get(
      `${config.llngUrl}/.well-known/openid-configuration`,
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/oidc_endpoints", (req, res) => {
  res.json(app.locals.endpoints);
});

app.get("/error", (req, res) => {
  res.status(401).json({ error: "Authentication failed" });
});

// Start server
initializePassport()
  .then(() => {
    app.listen(config.port, () => {
      console.log(
        `LLNG OIDC Client listening on http://localhost:${config.port}`,
      );
      console.log(`LLNG URL: ${config.llngUrl}`);
      console.log(`Client ID: ${config.clientId}`);
      console.log(`Redirect URI: ${config.redirectUri}`);
      console.log(`Scope: ${config.scope}`);
      console.log(`PKCE: ${config.pkce}`);
    });
  })
  .catch((error) => {
    console.error("Failed to initialize:", error);
    process.exit(1);
  });
