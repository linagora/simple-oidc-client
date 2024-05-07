# `llng` shell script

`llng` is a little script that allows you to interact with a LLNG server.

## Usage

```shell
$ llng <options> <command>
```

## Available commands

* **whoami**: simply return your id
* **languages**: get supported languages
* **llng_cookie**: get LLNG cookie
* **access_token**: get an OpenID-Connect `access_token`
* **id_token**: get an OpenID-Connect `id_token`
* **refresh_token**: get an OpenID-Connect `refresh_token`

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
