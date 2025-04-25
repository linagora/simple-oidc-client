# `llng` shell script

`llng` is a little script that allows you to interact with a LLNG server.

## Usage

```shell
$ llng <options> <command> <parameters>
```

## Available commands

* **whoami**: simply return your id
* **languages**: get supported languages _(JSON)_
* **llng_cookie**: get LLNG cookie
* **logout**: disconnect
* OpenID-Connect commands:
  * **oidc_metadata**: get OpenID-Connect metadata
  * **oidc_endpoints**: get OpenID-Connect endpoints _(from metadata)_
  * **oidc_tokens**: get the raw response of OIDC `/token` query _(JSON)_
  * **access_token**: get an OpenID-Connect `access_token`
  * **id_token**: get an OpenID-Connect `id_token`
  * **refresh_token**: get an OpenID-Connect `refresh_token`
  * **user_info**: get OpenID-Connect response to `/userinfo` query _(JSON)_.
    If no `access_token` is given in parameters, will query a new one using
    `getOidcTokens()`
  * **introspection**: get OpenID-Connect response to `/introspect`
    query _(JSON)_. If no `access_token` is given in parameters, will query a
    new one using `getOidcTokens()`
* Experimental commands:
  * **matrix_token**: get a Matrix `access_token` from a Matrix server
    connected to LLNG using OpenID-Connect
  * **matrix_federation_token**: get a Matrix federation `access_token`.
    if no Matrix token is given in arguments, call **matrix_token** to get
    an internal `access_token`.
  * **matrix_token_exchange** _(experimental)_: ask for tokens using a Matrix
    federation `access_token`. Arguments:
    - **Matrix token** _(required)_: a "federation" `access_token` given by
      [`/_matrix/client/v3/user/@user:domain.tld/openid/request_token`](https://spec.matrix.org/latest/client-server-api/#openid)
    - **Subject issuer** _(required)_: the Matrix "server name"
    - **Audience** _(optional)_: the `client_id` of requested relying party

## Options

You'll be prompted for any missing option

* **--cookie-jar**: where to store LLNG sessions. Default: `~/.cache/llng-cookies`
* **--login**: your LLNG login _(alias: **--user**)_
* **--password**: your LLNG password
* **--llng-server**: LLNG portal hostname _(with :port)_, used to calculate
* **--llng-url**: LLNG portal URL. Default: `https://<value of --llng-server>`.
* **--choice**: when LLNG uses [Choice](https://lemonldap-ng.org/documentation/latest/authchoice.html), indicate here the authentication to use. Example: `lmAuth=A_LDAP`

Debug options:
* **--debug**: display [curl](https://manpages.debian.org/bookworm/curl/curl.1.en.html) commands
* **--curl-opts**: options to add to each curl commands

OpenID-Connect options:
* application credentials:
  * **--client-id**: the application ID
  * **--client_secret**: the application secret _(if client isn't "public")_
  * **--pkce**: use [PKCE](https://www.rfc-editor.org/rfc/rfc7636)
* **--redirect-uri**: one authorized redirect uri of the OpenID-Connect application
* **--scope**: the wanted scope. Default: `openid profile email`
* **--access-token**: when given, use the given `access_token` instead of trying to get one
* **--refresh-token**: when given, try to get token using the given `refresh_token`

Experimental options:
* Matrix queries
  * **--matrix-server**: Matrix server
  * **--matrix-user**: Matrix address _(default: `@<value of --login>:<domain of --llng-server>`

## Using this inside a shell program

To use this inside a shell program, you can simple "source" the [llng-lib.sh](./llng-lib.sh)
file. Then you'll have these functions, corresponding to the different commands:

* **llng_connect**: establish LLNG connexion _(== get a valid cookie)_
* **getLanguages**
* **getLlngId**
* **getOidcMetadata**
* **getOidcEndpoints**
* PKCE:
  * **getCodeVerifier**
  * **getCodeChallenge**
* **getOidcTokens**
* **getAccessToken**
* **getIdToken**
* **getRefreshToken**
* **getUserInfo**
* **getIntrospection**
* **getAccessTokenFromMatrixToken**
* **getMatrixToken**
* **getMatrixFederationToken**

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
