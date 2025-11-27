# OIDC Viewer: simple OIDC frontend

Simple OpenID Connect compatible token and claims viewer. Its goal is to make easy to validate STS servers configuration
and fetch an access token for any given scope. It only supports the authorization_code authentication with PKCE always 
enabled.

TODO: Screenshots

> ⚠ This should not be used on a publicly exposed server. This is meant as a locally self-hosted tool that can be ran
> using docker-compose.

# Features

- Supports the following authentication methods:
  - `authorization_code` with Proof Key for Code Exchange (PKCE).



