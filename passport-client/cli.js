#!/usr/bin/env node

/**
 * LemonLDAP::NG OIDC Client CLI
 *
 * Authors: Xavier Guimard <xguimard@linagora.com>
 *
 * Licence: GPL V3 https://www.gnu.org/licenses/gpl-3.0.en.html
 */

const { program } = require("commander");
const OIDCClient = require("./lib/oidc-client");

const VERSION = "0.1.0";

program
  .name("llng")
  .description("LemonLDAP::NG OpenID-Connect client (Node.js/passport-oauth2)")
  .version(VERSION)
  .option("--llng-cookie <cookie>", "Use existing LemonLDAP cookie")
  .option("-c, --cookie-jar <file>", "Cookie jar file")
  .option("-u, --user <login>", "Login username")
  .option("-P, --prompt", "Prompt for password")
  .option("-p, --password <password>", "LLNG password")
  .option("-h, --llng-server <server>", "LLNG server hostname")
  .option("-H, --llng-url <url>", "LLNG full URL")
  .option("--debug", "Enable debug output")
  .option("-i, --client-id <id>", "OAuth2 client ID")
  .option("-s, --client-secret <secret>", "OAuth2 client secret")
  .option("-k, --pkce", "Enable PKCE")
  .option("-r, --redirect-uri <uri>", "Redirect URI")
  .option("-o, --scope <scope>", "OAuth2 scope", "openid email profile")
  .option("--access-token <token>", "Existing access token")
  .option("--refresh-token <token>", "Existing refresh token")
  .option("--matrix-server <server>", "Matrix server")
  .option("--matrix-user <user>", "Matrix user")
  .option("--choice <choice>", "Authentication choice");

// Helper to create client from options
function createClient(options) {
  return new OIDCClient({
    llngServer: options.llngServer,
    llngUrl: options.llngUrl,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scope: options.scope,
    pkce: options.pkce,
    debug: options.debug,
    accessToken: options.accessToken,
    refreshToken: options.refreshToken,
  });
}

// Helper for JSON output
function jsonOutput(data) {
  console.log(JSON.stringify(data, null, 2));
}

// Commands
program
  .command("whoami")
  .description("Get current user identity")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      if (opts.user) {
        await client.llngConnect(opts.user, opts.password);
      }
      const result = await client.whoami();
      console.log(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("languages")
  .description("Get available languages")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      const result = await client.getLanguages();
      jsonOutput(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("logout")
  .description("Logout from LLNG")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      const result = await client.logout();
      console.log(result ? "Logged out" : "Logout failed");
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("oidc_metadata")
  .description("Get OIDC metadata")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      const result = await client.getOidcMetadata();
      jsonOutput(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("oidc_endpoints")
  .description("Get OIDC endpoints")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      const result = await client.getOidcEndpoints();
      for (const [key, value] of Object.entries(result)) {
        console.log(`${key.toUpperCase()}_ENDPOINT=${value}`);
      }
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("oidc_tokens")
  .description("Get all OIDC tokens")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      if (opts.user) {
        await client.llngConnect(opts.user, opts.password);
      }
      const result = await client.getOidcTokens();
      jsonOutput(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("access_token")
  .description("Get access token")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      if (opts.user) {
        await client.llngConnect(opts.user, opts.password);
      }
      const result = await client.getAccessToken();
      console.log(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("id_token")
  .description("Get ID token")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      if (opts.user) {
        await client.llngConnect(opts.user, opts.password);
      }
      const result = await client.getIdToken();
      console.log(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("refresh_token")
  .description("Get refresh token")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      if (opts.user) {
        await client.llngConnect(opts.user, opts.password);
      }
      const result = await client.getRefreshToken();
      console.log(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("user_info [token]")
  .description("Get user info from access token")
  .action(async (token) => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      if (opts.user) {
        await client.llngConnect(opts.user, opts.password);
      }
      const result = await client.getUserInfo(token || opts.accessToken);
      jsonOutput(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("introspection [token]")
  .description("Introspect token")
  .action(async (token) => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      if (opts.user) {
        await client.llngConnect(opts.user, opts.password);
      }
      const result = await client.getIntrospection(token || opts.accessToken);
      jsonOutput(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("matrix_token")
  .description("Get Matrix token")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      if (opts.user) {
        await client.llngConnect(opts.user, opts.password);
      }
      if (!opts.matrixServer) {
        console.error("Error: --matrix-server is required");
        process.exit(1);
      }
      const result = await client.getMatrixToken(opts.matrixServer);
      console.log(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("matrix_federation_token")
  .description("Get Matrix federation token")
  .action(async () => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      if (!opts.matrixServer || !opts.matrixUser) {
        console.error("Error: --matrix-server and --matrix-user are required");
        process.exit(1);
      }
      const result = await client.getMatrixFederationToken(
        opts.matrixServer,
        opts.matrixUser,
      );
      console.log(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program
  .command("matrix_token_exchange <matrix_token> <subject_issuer> [audience]")
  .description("Exchange Matrix token for access token")
  .action(async (matrixToken, subjectIssuer, audience) => {
    try {
      const opts = program.opts();
      const client = createClient(opts);
      const result = await client.getAccessTokenFromMatrixToken(
        matrixToken,
        subjectIssuer,
        audience,
      );
      jsonOutput(result);
    } catch (error) {
      console.error("Error:", error.message);
      process.exit(1);
    }
  });

program.parse();
