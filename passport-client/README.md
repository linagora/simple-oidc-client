# LemonLDAP::NG OIDC Client (Node.js/passport-oauth2)

Équivalent Node.js du client shell `sh/llng` utilisant passport-oauth2.

## Installation

```bash
npm install
```

## Utilisation CLI

```bash
# Aide
./cli.js --help

# Obtenir les métadonnées OIDC
./cli.js -H https://auth.example.com oidc_metadata

# Obtenir un access token
./cli.js -H https://auth.example.com -u user -p password -i client_id -s client_secret -r http://localhost:9876/callback access_token

# Obtenir les informations utilisateur
./cli.js -H https://auth.example.com --access-token <token> -i client_id -s client_secret user_info

# Avec PKCE
./cli.js -H https://auth.example.com -u user -p password -i client_id -k -r http://localhost:9876/callback access_token

# Introspection
./cli.js -H https://auth.example.com -i client_id -s client_secret --access-token <token> introspection
```

## Utilisation serveur web

```bash
# Configuration via variables d'environnement
export LLNG_URL=https://auth.example.com
export CLIENT_ID=my-client
export CLIENT_SECRET=my-secret
export REDIRECT_URI=http://localhost:9876/callback
export SCOPE="openid email profile"
export PKCE=true  # optionnel

# Démarrer le serveur
npm start
```

Puis ouvrir http://localhost:9876 dans un navigateur.

### Endpoints du serveur

| Endpoint | Description |
|----------|-------------|
| `/` | Statut d'authentification |
| `/login` | Démarrer le flux OAuth2 |
| `/callback` | Callback OAuth2 |
| `/logout` | Déconnexion |
| `/whoami` | Identité de l'utilisateur |
| `/tokens` | Tous les tokens |
| `/access_token` | Access token brut |
| `/id_token` | ID token brut |
| `/refresh_token` | Refresh token brut |
| `/user_info` | Informations utilisateur |
| `/introspection` | Introspection du token |
| `/oidc_metadata` | Métadonnées OIDC |
| `/oidc_endpoints` | Endpoints OIDC |

## Options CLI

| Option | Description |
|--------|-------------|
| `-H, --llng-url <url>` | URL complète du serveur LLNG |
| `-h, --llng-server <server>` | Hostname du serveur LLNG |
| `-u, --user <login>` | Nom d'utilisateur |
| `-p, --password <password>` | Mot de passe |
| `-i, --client-id <id>` | Client ID OAuth2 |
| `-s, --client-secret <secret>` | Client secret OAuth2 |
| `-r, --redirect-uri <uri>` | URI de redirection |
| `-o, --scope <scope>` | Scopes OAuth2 |
| `-k, --pkce` | Activer PKCE |
| `--access-token <token>` | Access token existant |
| `--refresh-token <token>` | Refresh token existant |
| `--debug` | Mode debug |

## Commandes CLI

| Commande | Description |
|----------|-------------|
| `whoami` | Identité de l'utilisateur connecté |
| `languages` | Langues disponibles |
| `logout` | Déconnexion |
| `oidc_metadata` | Métadonnées OIDC |
| `oidc_endpoints` | Endpoints OIDC |
| `oidc_tokens` | Tous les tokens |
| `access_token` | Obtenir l'access token |
| `id_token` | Obtenir l'ID token |
| `refresh_token` | Obtenir le refresh token |
| `user_info [token]` | Informations utilisateur |
| `introspection [token]` | Introspection du token |
| `matrix_token` | Token Matrix |
| `matrix_federation_token` | Token fédération Matrix |
| `matrix_token_exchange` | Échange de token Matrix |

## Licence

GPL V3 - https://www.gnu.org/licenses/gpl-3.0.en.html
