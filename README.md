# OIDC Viewer

A simple OpenID Connect client to visualize your user tokens and claims. It allows you to provide OIDC-compatible IdP connection settings to fetch a user token. It can be used to visualize, explore and investigation your authorization flow.

> ⚠ This should not be used on a publicly exposed server or as a production OIDC client. This is meant to be used as a locally self-hosted tool for development purpose.

![screenshot](screenshot_signin.png)
![screenshot](screenshot_view.png)

# Features

- Supports the following authentication methods:
  - [x] `authorization_code` with Proof Key for Code Exchange (PKCE).
  - [ ] `client_credentials`

# Quick deployment guide

> This assumes that you are using the default settings provided in the repository.

- **(Optional)** Install root CA from [mkcert](https://github.com/FiloSottile/mkcert):

```shell
mkcert --install
```

- Create certificates using [mkcert](https://github.com/FiloSottile/mkcert):

```shell
mkcert --cert-file ./deploy/certs/localhost.crt \
       --key-file ./deploy/certs/localhost.key \ 
       localhost 127.0.0.1 ::1 "oidc.localhost"
```

- Copy `presets.env.sample` to `presets.env` and set your own presets.
- Run `docker compose up -d`
- Open https://oidc.localhost

# Custom usage

The `DataProtection-Keys` directory is mounted to re-use the same keys across container restarts. As mentioned, this is only for development purpose thus keys are persisted in plain text and should not be considered secure.

## Simple docker compose setup

```dockerfile
services:
  oidc-viewer:
    image: mistcentauri/oidc-viewer:latest
    container_name: oidc-viewer
    restart: unless-stopped
    env_file: "presets.env"
    volumes:
      - aspnet_keys:/home/app/.aspnet/DataProtection-Keys
    ports:
      - "8080:8080"

volumes:
  aspnet_keys:
```

## Using caddy as a reverse proxy

> *This is the setup provided as a default with the repository*

- Caddyfile

```caddyfile
<name>.localhost {
  reverse_proxy oidc-viewer:8080
}
```

- docker-compose.yaml

```dockerfile
services:
  caddy:
    image: docker.io/library/caddy:latest
    container_name: caddy
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config

  oidc-viewer:
    image: mistcentauri/oidc-viewer:latest
    container_name: oidc-viewer
    restart: unless-stopped
    env_file: "presets.env"
    volumes:
      - aspnet_keys:/home/app/.aspnet/DataProtection-Keys
    ports:
      - "8080"

volumes:
  caddy_data:
  caddy_config:
  aspnet_keys:
```

# Build

Build the Docker image locally using the following command:

```bash
dotnet publish --os linux --arch x64 /t:PublishContainer ./src
```

# License
OIDC Viewer is MIT licensed. See the [LICENSE](LICENSE) file for details.
