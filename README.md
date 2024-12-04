To configure Sentienl IDP (Keycloak) as an identity broker to federate authentication with Auth0 and obtain access tokens from both IDP systems, there are 2 options:
## 1. SSO
This sample will demostrate how to use sso flow with loopback way to let public application to get both access tokens from auth0 and keycloak via single user login.

## 2. Token exchange
Keycloak's token exchange is a feature that allows one token to be exchanged for another. It is useful when you need to interact with a downstream service on behalf of a user or client, enabling delegation of authorization.


