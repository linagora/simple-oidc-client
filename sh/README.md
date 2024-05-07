# `llng` shell script

`llng` is a little script that allows you to interact with a LLNG server.

## Usage

```shell
$ llng <options> <command>
```

## Available commands

* **whoami**: simply return your id
* **languages**: get supported languages _(JSON)_
* **llng_cookie**: get LLNG cookie
* **oidc_tokens**: get the raw response of OIDC `/token` query _(JSON)_
* **access_token**: get an OpenID-Connect `access_token`
* **id_token**: get an OpenID-Connect `id_token`
* **refresh_token**: get an OpenID-Connect `refresh_token`
* **user_info**: get OpenID-Connect response to `/userinfo` query _(JSON)_

## Options

You'll be prompted for any missing option

* **--cookie-jar**: where to store LLNG sessions. Default: `~/.cache/llng-cookies`
* **--login**: your LLNG login
* **--password**: your LLNG password
* **--llng-server**: LLNG portal hostname _(with :port)_, used to calculate **--llng-url** if not given. Default: `localhost:19876`
* **--llng-url**: LLNG portal URL. Default: `https://<value of --llng-server>`

OpenID-Connect options:
* application credentials:
  * **--client-id**: the application ID
  * **--client_secret**: the application secret _(if client isn't "public")_
* **--redirect-uri**: one authorized redirect uri of the OpenID-Connect application
* **--scope**: the wanted scope. Default: `openid profile email`

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
