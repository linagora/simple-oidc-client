import fetch from 'node-fetch';
import { Issuer, generators } from 'openid-client';
import express from 'express';
import bodyParser from 'body-parser';
import jwt_decode from 'jwt-decode';

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

let client;
let issuerMetadata;
let urlBack;
let uriBack;
let scopes;
let code_verifier;
let opaque;

const returnError = (res) => {
  return err => {
    console.error('ERROR', err);
    res.send(`<html>
      <title>Config</title>
      <body>Not OK
      <pre>${err}</pre>
      </body>
      </html>`)
  }
}

/**
 * Run
 */

app.get('/', (req, res) => {
  if (client == null) {
    return res.redirect('/config');
  }
  code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);
  const url = client.authorizationUrl({
    scope: scopes,
    resource: 'https://my.api.example.com/resource/32178',
    code_challenge,
    code_challenge_method: 'S256',
  });
  res.send(`<html>
    <title>Start OIDC</title>
    <body>
      Ready to launch OIDC authorization flow
      <ul>
        <li>Code: ${code_challenge}</li>
        <li>Scopes: ${scopes}</li>
      </ul>
      <a href="${url}">Let's go!</a>
    </body>
  </html>`)
});

const back = (req, res) => {
  const rt = returnError(res)
  try {
    const params = client.callbackParams(req);
    client.callback(
      urlBack,
      params, { code_verifier }
    ).then( tokenSet => {
      // keys: refresh_token, id_token, token_type, access_token expires_at, session_state
      const access_token = tokenSet.access_token;
      const id_token = tokenSet.id_token;
      client.userinfo(access_token).then(userInfo => {
        res.send(`<html>
        <title>Back</title>
        <body>
          OIDC code
          <ul>
            <li>ID_Token: <pre>${JSON.stringify(jwt_decode(id_token), null, 2)}</pre></li>
            <li>Access_Token: <pre>${opaque ? access_token : JSON.stringify(jwt_decode(access_token), null, 2)}</pre></li>
            <li>User info response: <pre>${JSON.stringify(userInfo, null, 2)}</pre></li>
          </ul>
        </body>
      </html>`);
      })
    }).catch(rt);
  } catch(e) {
    rt(e);
  }
};

/**
 * Configuration
 */

app.get('/config', (req, res) => {
  res.send(`<html>
  <title>Config</title>
  <body>
    <form method="POST">
      <table border="0"><tbody>
        <tr><td>Who am I</td><td><input name="whoami" /></td></tr>
        <tr><td>Issuer</td><td><input name="issuer" /></td></tr>
        <tr><td>Client ID</td><td><input name="clientid" /></td></tr>
        <tr><td>Client secret</td><td><input name="clientsecret" /></td></tr>
        <tr><td>Redirect URI</td><td><input name="redirecturi" /></td></tr>
        <tr><td>Scopes</td><td><input name="scopes" value="openid email profile" /></td></tr>
        <tr><td>Algorithm</td><td><input name="alg" value="RS512" /></td></tr>
        <tr><td>Opaque token</td><td><input name="opaque" value="0" /></td></tr>
      </tbody></table>
      <input type="submit" value="OK">
    </form>
  </body>
</html>`);
});

app.post('/config', (req, res) => {
  const rt = returnError(res)
  console.log('Got body:', req.body);
  const body = req.body;

  Issuer.discover(body.issuer).then( issuer => {
    console.log('Discovered issuer %s', issuer.issuer);
    issuerMetadata = issuer.metadata;
    try {
      client = new issuer.Client({
        client_id: body.clientid,
        client_secret: body.clientsecret,
        redirect_uris: [body.redirecturi],
        id_token_signed_response_alg: body.alg,
      });
      console.log('Client created');
      urlBack = body.redirecturi;
      uriBack = body.redirecturi.replace(/^https?:\/\/[^/]+/, '');
      scopes = body.scopes;
      opaque = body.opaque;
      res.send(`<html>
        <title>Config</title>
        <body>
          OK<br>
          <a href="/">Try it</a>
        </body>
      </html>`);
    } catch (e) {
      rt(e);
    };
  }).catch(rt)
})

app.get('*', (req, res) => {
  if (req.path === uriBack) {
    return back(req, res)
  }
  console.log('res', req.path);
  res.send(`<html>
    <title>Config</title>
    <body>
      Undefined URI
    </body>
  </html>`);
});

app.listen(5000);