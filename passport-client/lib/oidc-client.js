/**
 * LemonLDAP::NG OIDC Client using passport-oauth2
 *
 * Authors: P Vilarem <pvilarem@linagora.com>
 *          X Guimard <xguimard@linagora.com>
 *
 * Licence: GPL V3 https://www.gnu.org/licenses/gpl-3.0.en.html
 */

const axios = require('axios');
const crypto = require('crypto');
const { promisify } = require('util');
const readline = require('readline');

class OIDCClient {
  constructor(options = {}) {
    this.llngServer = options.llngServer || 'auth.example.com:19876';
    this.llngUrl = options.llngUrl || null;
    this.clientId = options.clientId || null;
    this.clientSecret = options.clientSecret || null;
    this.redirectUri = options.redirectUri || 'http://localhost:9876/callback';
    this.scope = options.scope || 'openid email profile';
    this.pkce = options.pkce || false;
    this.debug = options.debug || false;

    this.cookies = {};
    this.accessToken = options.accessToken || null;
    this.idToken = null;
    this.refreshToken = options.refreshToken || null;
    this.rawTokens = null;

    this.endpoints = {};
    this.connected = false;

    // PKCE
    this.codeVerifier = null;
    this.codeChallenge = null;

    // Build URL if not provided
    if (!this.llngUrl) {
      this.llngUrl = this._buildLlngUrl();
    }

    // Axios instance with cookie support
    this.client = axios.create({
      headers: {
        'User-Agent': 'LLNG-Client/2.20.0',
        'Accept': 'application/json'
      },
      maxRedirects: 0,
      validateStatus: (status) => status < 500
    });
  }

  _buildLlngUrl() {
    let url = this.llngServer.replace(/\/+$/, '');
    if (!url.match(/^https?:\/\//)) {
      url = 'https://' + url;
    }
    return url;
  }

  _log(...args) {
    if (this.debug) {
      const time = new Date().toISOString();
      console.error(`[${time}]`, ...args);
    }
  }

  _getCookieHeader() {
    return Object.entries(this.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  _parseCookies(setCookieHeaders) {
    if (!setCookieHeaders) return;
    const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const header of headers) {
      const match = header.match(/^([^=]+)=([^;]*)/);
      if (match) {
        this.cookies[match[1]] = match[2];
      }
    }
  }

  async _request(method, url, data = null, headers = {}) {
    const config = {
      method,
      url,
      headers: {
        ...headers,
        'Cookie': this._getCookieHeader()
      }
    };

    if (data) {
      if (typeof data === 'string') {
        config.data = data;
        config.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      } else {
        config.data = new URLSearchParams(data).toString();
        config.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      }
    }

    this._log(`${method} ${url}`);
    const response = await this.client(config);
    this._parseCookies(response.headers['set-cookie']);
    return response;
  }

  async askString(prompt) {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr
    });

    return new Promise((resolve) => {
      rl.question(`${prompt}: `, (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  async askPassword(prompt) {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr
    });

    return new Promise((resolve) => {
      process.stderr.write(`${prompt}: `);
      const stdin = process.stdin;
      const wasRaw = stdin.isRaw;
      stdin.setRawMode && stdin.setRawMode(true);

      let password = '';
      const onData = (char) => {
        char = char.toString();
        switch (char) {
          case '\n':
          case '\r':
          case '\u0004':
            stdin.setRawMode && stdin.setRawMode(wasRaw);
            stdin.removeListener('data', onData);
            process.stderr.write('\n');
            rl.close();
            resolve(password);
            break;
          case '\u0003':
            process.exit();
            break;
          case '\u007F':
            password = password.slice(0, -1);
            break;
          default:
            password += char;
        }
      };
      stdin.on('data', onData);
    });
  }

  // PKCE helpers
  _generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url').substring(0, 43);
  }

  _generateCodeChallenge(verifier) {
    return crypto
      .createHash('sha256')
      .update(verifier)
      .digest('base64url');
  }

  // OIDC Metadata
  async getOidcMetadata() {
    const url = `${this.llngUrl}/.well-known/openid-configuration`;
    try {
      const response = await this._request('GET', url);
      return response.data;
    } catch (error) {
      return null;
    }
  }

  async getOidcEndpoints() {
    const metadata = await this.getOidcMetadata();

    if (metadata) {
      this.endpoints = {
        authorization: metadata.authorization_endpoint,
        token: metadata.token_endpoint,
        userinfo: metadata.userinfo_endpoint,
        introspection: metadata.introspection_endpoint,
        endSession: metadata.end_session_endpoint
      };
    } else {
      this.endpoints = {
        authorization: `${this.llngUrl}/oauth2/authorize`,
        token: `${this.llngUrl}/oauth2/token`,
        userinfo: `${this.llngUrl}/oauth2/userinfo`,
        introspection: `${this.llngUrl}/oauth2/introspect`,
        endSession: `${this.llngUrl}/oauth2/logout`
      };
    }

    return this.endpoints;
  }

  // LemonLDAP::NG Connection
  async llngConnect(login, password, choice) {
    // Test if already connected and get CSRF token
    const response = await this._request('GET', this.llngUrl);

    // Already connected?
    if (response.status === 200 && response.data && response.data.id) {
      this.connected = true;
      return true;
    }

    // Get CSRF token from response
    let token = null;
    if (response.data && response.data.token) {
      token = response.data.token;
    }

    // Get login and password if not provided
    if (!login) {
      login = await this.askString('Login');
    }
    if (!password) {
      password = await this.askPassword('Password');
    }

    // Authenticate
    const authData = {
      user: login,
      password: password
    };
    if (token) {
      authData.token = token;
    }
    if (choice) {
      Object.assign(authData, choice);
    }

    const authResponse = await this._request('POST', this.llngUrl, authData);
    if (authResponse.data && authResponse.data.id && authResponse.data.id !== 'null') {
      this.connected = true;
      return true;
    } else {
      throw new Error(`Unable to connect: ${JSON.stringify(authResponse.data)}`);
    }
  }

  async whoami() {
    if (!this.connected) {
      await this.llngConnect();
    }
    const response = await this._request('GET', `${this.llngUrl}/mysession/?whoami`);
    return response.data.result;
  }

  async getLanguages() {
    const response = await this._request('GET', `${this.llngUrl}/languages`);
    return response.data;
  }

  async logout() {
    const response = await this._request('GET', `${this.llngUrl}/?logout=1`);
    return response.data.result === 1;
  }

  // OAuth2/OIDC Token handling
  async _queryToken() {
    if (!this.endpoints.authorization) {
      await this.getOidcEndpoints();
    }

    // Try refresh token first
    if (this.refreshToken) {
      try {
        const tokenData = {
          grant_type: 'refresh_token',
          client_id: this.clientId,
          refresh_token: this.refreshToken
        };

        const headers = {};
        if (this.clientSecret) {
          const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
          headers['Authorization'] = `Basic ${auth}`;
        }

        const response = await this._request('POST', this.endpoints.token, tokenData, headers);
        this.rawTokens = response.data;
        this._parseTokens();
        return;
      } catch (error) {
        this._log('Refresh token failed, trying full auth flow');
      }
    }

    // Full authorization code flow
    if (!this.connected) {
      await this.llngConnect();
    }

    if (!this.clientId) {
      this.clientId = await this.askString('Client ID');
    }
    if (!this.redirectUri) {
      this.redirectUri = await this.askString('Redirect URI');
    }

    // PKCE setup
    let pkceParams = '';
    if (this.pkce) {
      this.codeVerifier = this._generateCodeVerifier();
      this.codeChallenge = this._generateCodeChallenge(this.codeVerifier);
      pkceParams = `&code_challenge_method=S256&code_challenge=${this.codeChallenge}`;
    }

    // Build authorization URL
    let scopeParam = `scope=${encodeURIComponent(this.scope)}`;
    if (this.scope.includes('offline_access')) {
      scopeParam += '&prompt=consent';
    }

    const authUrl = `${this.endpoints.authorization}?client_id=${encodeURIComponent(this.clientId)}&redirect_uri=${encodeURIComponent(this.redirectUri)}&response_type=code&${scopeParam}${pkceParams}`;

    this._log('Authorization URL:', authUrl);

    // Request authorization
    const authResponse = await this._request('GET', authUrl, null, { 'Accept': 'text/html' });

    let code = null;

    // Check for consent form
    if (authResponse.data && typeof authResponse.data === 'string' && authResponse.data.includes('id="confirm"')) {
      const confirmMatch = authResponse.data.match(/id="confirm"[^>]*value="([^"]+)"/);
      if (confirmMatch) {
        const confirmResponse = await this._request('POST', authUrl, { confirm: confirmMatch[1] }, { 'Accept': 'text/html' });
        const location = confirmResponse.headers.location;
        if (location) {
          const codeMatch = location.match(/code=([^&#]+)/);
          if (codeMatch) code = codeMatch[1];
        }
      }
    } else {
      // Check for redirect with code
      const location = authResponse.headers.location;
      if (location) {
        const codeMatch = location.match(/code=([^&#]+)/);
        if (codeMatch) code = codeMatch[1];
      }
    }

    if (!code) {
      throw new Error('Unable to get OIDC code, check your parameters');
    }

    // Exchange code for tokens
    const tokenData = {
      grant_type: 'authorization_code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: this.scope,
      code: code
    };

    if (this.pkce && this.codeVerifier) {
      tokenData.code_verifier = this.codeVerifier;
    }

    const headers = {};
    if (this.clientSecret) {
      const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
      headers['Authorization'] = `Basic ${auth}`;
    }

    const tokenResponse = await this._request('POST', this.endpoints.token, tokenData, headers);
    this.rawTokens = tokenResponse.data;
    this._parseTokens();
  }

  _parseTokens() {
    if (this.rawTokens) {
      if (this.rawTokens.access_token) {
        this.accessToken = this.rawTokens.access_token;
      }
      if (this.rawTokens.id_token) {
        this.idToken = this.rawTokens.id_token;
      }
      if (this.rawTokens.refresh_token) {
        this.refreshToken = this.rawTokens.refresh_token;
      }
    }
  }

  async getOidcTokens() {
    if (!this.rawTokens) {
      await this._queryToken();
    }
    return this.rawTokens;
  }

  async getAccessToken() {
    if (!this.accessToken) {
      await this._queryToken();
    }
    return this.accessToken;
  }

  async getIdToken() {
    if (!this.idToken) {
      await this._queryToken();
    }
    return this.idToken;
  }

  async getRefreshToken() {
    if (!this.refreshToken) {
      await this._queryToken();
    }
    return this.refreshToken;
  }

  async getUserInfo(token) {
    if (!this.endpoints.userinfo) {
      await this.getOidcEndpoints();
    }

    token = token || this.accessToken;
    if (!token) {
      await this._queryToken();
      token = this.accessToken;
    }

    const response = await this._request('GET', this.endpoints.userinfo, null, {
      'Authorization': `Bearer ${token}`
    });
    return response.data;
  }

  async getIntrospection(token) {
    if (!this.endpoints.introspection) {
      await this.getOidcEndpoints();
    }

    token = token || this.accessToken;
    if (!token) {
      await this._queryToken();
      token = this.accessToken;
    }

    const headers = {};
    if (this.clientSecret) {
      const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
      headers['Authorization'] = `Basic ${auth}`;
    }

    const response = await this._request('POST', this.endpoints.introspection, { token }, headers);
    return response.data;
  }

  // Matrix support
  async getMatrixToken(matrixServer) {
    const matrixUrl = `https://${matrixServer}/_matrix/client`;

    // Get provider
    const loginResponse = await this._request('GET', `${matrixUrl}/v3/login`);
    const provider = loginResponse.data.flows[0]?.identity_providers[0]?.id;

    if (!this.connected) {
      await this.llngConnect();
    }

    // SSO redirect
    const ssoUrl = `${matrixUrl}/r0/login/sso/redirect/${provider}?redirectUrl=${encodeURIComponent('http://localhost:9876')}`;
    const ssoResponse = await this._request('GET', ssoUrl, null, { 'Accept': 'text/html' });

    // Follow redirects manually to get login token
    let location = ssoResponse.headers.location;
    let content = ssoResponse.data;

    while (location && !location.includes('loginToken=')) {
      const response = await this._request('GET', location, null, { 'Accept': 'text/html' });
      location = response.headers.location;
      content = response.data;
    }

    const loginTokenMatch = (location || content).match(/loginToken=([^"&]+)/);
    if (!loginTokenMatch) {
      throw new Error('Unable to get matrix login_token');
    }

    // Exchange for matrix token
    const matrixLoginResponse = await this._request('POST', `${matrixUrl}/v3/login`, JSON.stringify({
      initial_device_display_name: 'Passport Test Client',
      token: loginTokenMatch[1],
      type: 'm.login.token'
    }), { 'Content-Type': 'application/json' });

    return matrixLoginResponse.data.access_token;
  }

  async getMatrixFederationToken(matrixServer, matrixUser, matrixToken) {
    const matrixUrl = `https://${matrixServer}/_matrix/client`;

    if (!matrixToken) {
      matrixToken = await this.getMatrixToken(matrixServer);
    }

    const response = await this._request('POST', `${matrixUrl}/v3/user/${matrixUser}/openid/request_token`, '{}', {
      'Authorization': `Bearer ${matrixToken}`,
      'Content-Type': 'application/json'
    });

    return response.data.access_token;
  }

  async getAccessTokenFromMatrixToken(matrixToken, subjectIssuer, audience) {
    if (!this.endpoints.token) {
      await this.getOidcEndpoints();
    }

    const headers = {};
    if (this.clientSecret) {
      const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
      headers['Authorization'] = `Basic ${auth}`;
    }

    const response = await this._request('POST', this.endpoints.token, {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: this.clientId,
      subject_token: matrixToken,
      scope: this.scope,
      subject_issuer: subjectIssuer,
      audience: audience
    }, headers);

    return response.data;
  }
}

module.exports = OIDCClient;
