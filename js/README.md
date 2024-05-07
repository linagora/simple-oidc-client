# Simple JS OpenID-Connect test page

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

## License and copyright

Copyright: 2024 [Linagora](https://linagora.com)

These tools are a free softwares; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/.
