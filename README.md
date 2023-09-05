# Simple OIDC client

## Install

Install it using npm:
```shell
$ npm i -g simple-oidc-client
```

then the server is in your path _(`simple-oidc-client`)_

or clone the source repository:

```shell
$ git clone https://github.com/linagora/simple-oidc-client.git
$ cd simple-oidc-client
$ npm install
```
then the server is `./src/server.mjs`

## Use it to debug

* Launch this server
* Replace your relying party by this server. Example with nginx:
```nginx
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  ssl_certificate /etc/nginx/my-cert.crt;
  ssl_certificate_key /etc/nginx/my-cert.key;
  server_name tmail.client.fr;

  location / {
    proxy_pass http://localhost:5000;
    proxy_set_header Host $http_host;
  }
}
```
* Launch your browser and connect to your app. In this example: https://tmail.client.fr/
* Configure OIDC parameters with the values of your relying party and validate
* If it's OK, follow the link and launch OIDC flow, you'll see OIDC data

## Command line options

You can use command-line options to configure the OIDC client:

```
      --help           Show help                                       [boolean]
      --version        Show version number                             [boolean]
  -p, --port           Port to listen on                [number] [default: 5000]
  -i, --issuer         OIDC Issuer URL                                  [string]
  -n, --client-id      OIDC Client ID                                   [string]
  -s, --client-secret  OIDC Client Secret                               [string]
  -r, --redirect-uri   Redirection URI                                  [string]
      --alg            Algorithm                     [string] [default: "RS512"]
      --scopes         Scopes         [string] [default: "openid email profile"]
      --opaque-token   Access token is opaque         [boolean] [default: false]
```

## GET parameters

When app is configured, if it is called with a "auto" parameter in the GET
query, it launches automatically the OIDC flow.
