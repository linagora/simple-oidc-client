#!/usr/bin/node

import fetch from 'node-fetch';
import { Issuer, generators } from 'openid-client';
import express from 'express';
import bodyParser from 'body-parser';
import jwt_decode from 'jwt-decode';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

let client = '';
let issuerMetadata = '';
let urlBack = '';
let uriBack = '';
let scopes = 'openid profile email';
let code_verifier;
let opaque = 0;
let issuerUrl = '';
let alg = 'RS512'
let redirectUri = '';
let clientId = '';
let clientSecret = '';
let pkce = false;

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
  if (req.query.openidconnectcallback) {
    return back(req,res)
  }
  if (!client) {
    return res.redirect('/config');
  }
  code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);
  const _opts = {
    scope: scopes,
    //resource: 'https://my.api.example.com/resource/32178',
  };
  if (pkce) {
    console.info('PKCE is set', pkce);
    _opts.code_challenge = code_challenge;
    _opts.code_challenge_method = 'S256';
  }
  console.debug('ARGS', _opts);
  const url = client.authorizationUrl(_opts);
  if (req.query && req.query.auto != undefined) {
    res.redirect(url);
  } else {
    res.send(`<html>
      <title>Start OIDC</title>
      <body>
        Ready to launch OIDC authorization flow
        ${pkce ? `
        <ul>
          <li>Code: ${code_challenge}</li>
          <li>Scopes: ${scopes}</li>
        </ul>
        ` : ''}
        <a href="${url}">Let's go!</a>
      </body>
    </html>`);
  }
});

const back = (req, res) => {
  const rt = returnError(res)
  try {
    const params = client.callbackParams(req);
    console.log('Received parameters', params)
    const args = [urlBack, params];
    if (pkce) args.push({ code_verifier });
    console.log('POST PARAMS', args)
    client.callback(...args)
    .then( tokenSet => {
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
            <li>Access_Token: <pre>${opaque == 1 ? access_token : JSON.stringify(jwt_decode(access_token), null, 2)}</pre></li>
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
        <tr><td>Issuer</td><td><input name="issuer" value="${issuerUrl}" /></td></tr>
        <tr><td>Client ID</td><td><input name="clientid" value="${clientId}" /></td></tr>
        <tr><td>Client secret</td><td><input type="password" name="clientsecret" value="${clientSecret}" /></td></tr>
        <tr><td>Redirect URI</td><td><input name="redirecturi" value="${redirectUri}" /></td></tr>
        <tr><td>Scopes</td><td><input name="scopes" value="${scopes}" /></td></tr>
        <tr><td>Algorithm</td><td><input name="alg" value="${alg}" /></td></tr>
        <tr><td>Opaque token</td><td><input name="opaque" value="${opaque}" /></td></tr>
        <tr><td>PKCE</td><td><input name="pkce" value="${pkce}" /></td></tr>
      </tbody></table>
      <input type="submit" value="OK">
    </form>
  </body>
</html>`);
});

app.post('/config', (req, res) => {
  const rt = returnError(res)
  const body = req.body;
  discover(body.issuer, body.clientid, body.clientsecret, body.redirecturi, body.alg, body.scopes, body.opaque, body.pkce)
    .then( () => {
      res.send(`<html>
        <title>Config</title>
        <body>
          OK<br>
          <a href="/">Try it</a>
        </body>
      </html>`);
    })
    .catch(rt)
})

/**
 * Default cathc: detect back-channel or warn
 */
app.get('*', (req, res) => {
  if (req.path === uriBack) {
    return back(req, res)
  }
  res.send(`<html>
    <title>Config</title>
    <body>
      Undefined URI
    </body>
  </html>`);
});

const discover = async (_issuerUrl, client_id, client_secret, redir, id_token_signed_response_alg, _scopes, _opaque, _pkce) => {
  const issuer = await Issuer.discover(_issuerUrl);
  issuerUrl = _issuerUrl;
  clientId = client_id;
  clientSecret = client_secret;
  alg = id_token_signed_response_alg;
  scopes = _scopes;
  opaque = _opaque;
  pkce = _pkce == 1 ? true : false;
  redirectUri = redir;
  urlBack = redir;
  uriBack = redir.replace(/^https?:\/\/[^/]+/, '');
  console.log('Discovered issuer %s', issuer.issuer);
  issuerMetadata = issuer.metadata;
  client = new issuer.Client({
    client_id,
    client_secret,
    redirect_uris: [redir],
    id_token_signed_response_alg,
  });
  console.error('PKCE', [_pkce,pkce]);
}

// console.log(yargs(hideBin(process.argv)).argv);
const argv = yargs(hideBin(process.argv))
  .option('port', {
    alias: 'p',
    type: 'number',
    default: 5000,
    describe: 'Port to listen on'
  })
  .option('issuer', {
    alias: 'i',
    type: 'string',
    describe: 'OIDC Issuer URL',
  })
  .option('client-id', {
    alias: 'n',
    type: 'string',
    describe: 'OIDC Client ID',
  })
  .option('client-secret', {
    alias: 's',
    type: 'string',
    describe: 'OIDC Client Secret',
  })
  .option('redirect-uri', {
    alias: 'r',
    type: 'string',
    describe: 'Redirection URI',
  })
  .option('alg', {
    type: 'string',
    describe: 'Algorithm',
    default: 'RS512',
  })
  .option('scopes', {
    type: 'string',
    describe: 'Scopes',
    default: 'openid email profile',
  })
  .option('opaque-token', {
    type: 'boolean',
    describe: 'Access token is opaque',
    default: false,
  })
  .option('pkce', {
    type: 'boolean',
    describe: 'Use PKCE',
    default: false,
  })
  .argv;

new Promise((resolve, reject) => {
  if (argv.clientId || argv.clientSecret || argv.redirectUri || argv.issuer ) {
    if (!(argv.clientId && argv.clientSecret && argv.redirectUri)) {
      console.error('Need --client-id and --client-secret and --redirect-uri and --issuer');
      process.exit(1);
    }
    discover(argv.issuer, argv.clientId, argv.clientSecret, argv.redirectUri, argv.alg, argv.scopes, (argv.opaque ? 1 : 0), (argv.pkce ? 1 : 0))
    .then(resolve)
    .catch(reject)
  } else {
    resolve();
  }
}).then(() => {
  console.log(`Server started on port ${argv.port}`);
  app.listen(argv.port);
}).catch( e => {
  console.error('Unable to initialize client', e);
  process.exit(1);
})
