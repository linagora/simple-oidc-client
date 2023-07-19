# Simple OIDC client

## Prepare

```shell
$ git clone https://github.com/linagora/simple-oidc-client.git
$ cd simple-oidc-client
$ npm install
```

## Use it to debug

* Launch this server _(`node server.js`)_ 
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
