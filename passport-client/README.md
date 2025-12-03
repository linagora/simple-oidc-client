# LemonLDAP::NG OIDC Client (Node.js/passport-oauth2)

Node.js equivalent of the `sh/llng` shell client using passport-oauth2.

## Installation

```bash
npm install
```

## CLI Usage

```bash
# Help
./cli.js --help

# Get OIDC metadata
./cli.js -H https://auth.example.com oidc_metadata

# Get an access token
./cli.js -H https://auth.example.com -u user -p password -i client_id -s client_secret -r http://localhost:9876/callback access_token

# Get user info
./cli.js -H https://auth.example.com --access-token <token> -i client_id -s client_secret user_info

# With PKCE
./cli.js -H https://auth.example.com -u user -p password -i client_id -k -r http://localhost:9876/callback access_token

# Introspection
./cli.js -H https://auth.example.com -i client_id -s client_secret --access-token <token> introspection
```

## Web Server Usage

```bash
# Configuration via environment variables
export LLNG_URL=https://auth.example.com
export CLIENT_ID=my-client
export CLIENT_SECRET=my-secret
export REDIRECT_URI=http://localhost:9876/callback
export SCOPE="openid email profile"
export PKCE=true  # optional

# Start the server
npm start
```

Then open http://localhost:9876 in a browser.

### Server Endpoints

| Endpoint          | Description           |
| ----------------- | --------------------- |
| `/`               | Authentication status |
| `/login`          | Start OAuth2 flow     |
| `/callback`       | OAuth2 callback       |
| `/logout`         | Logout                |
| `/whoami`         | User identity         |
| `/tokens`         | All tokens            |
| `/access_token`   | Raw access token      |
| `/id_token`       | Raw ID token          |
| `/refresh_token`  | Raw refresh token     |
| `/user_info`      | User information      |
| `/introspection`  | Token introspection   |
| `/oidc_metadata`  | OIDC metadata         |
| `/oidc_endpoints` | OIDC endpoints        |

## CLI Options

| Option                         | Description            |
| ------------------------------ | ---------------------- |
| `-H, --llng-url <url>`         | Full LLNG server URL   |
| `-h, --llng-server <server>`   | LLNG server hostname   |
| `-u, --user <login>`           | Username               |
| `-p, --password <password>`    | Password               |
| `-i, --client-id <id>`         | OAuth2 client ID       |
| `-s, --client-secret <secret>` | OAuth2 client secret   |
| `-r, --redirect-uri <uri>`     | Redirect URI           |
| `-o, --scope <scope>`          | OAuth2 scopes          |
| `-k, --pkce`                   | Enable PKCE            |
| `--access-token <token>`       | Existing access token  |
| `--refresh-token <token>`      | Existing refresh token |
| `--debug`                      | Debug mode             |

## CLI Commands

| Command                   | Description             |
| ------------------------- | ----------------------- |
| `whoami`                  | Connected user identity |
| `languages`               | Available languages     |
| `logout`                  | Logout                  |
| `oidc_metadata`           | OIDC metadata           |
| `oidc_endpoints`          | OIDC endpoints          |
| `oidc_tokens`             | All tokens              |
| `access_token`            | Get access token        |
| `id_token`                | Get ID token            |
| `refresh_token`           | Get refresh token       |
| `user_info [token]`       | User information        |
| `introspection [token]`   | Token introspection     |
| `matrix_token`            | Matrix token            |
| `matrix_federation_token` | Matrix federation token |
| `matrix_token_exchange`   | Matrix token exchange   |

## License

GPL V3 - https://www.gnu.org/licenses/gpl-3.0.en.html
