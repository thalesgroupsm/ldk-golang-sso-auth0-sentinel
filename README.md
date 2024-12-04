To configure Keycloak as an identity broker to federate authentication with Auth0 and obtain access tokens from both systems, there are 3 options
## 1. SSO
This sample will demostrate how to use sso flow with loopback way to let public application to get both access tokens from auth0 and keycloak via single user login.

## 2. Token exchange
Keycloak's token exchange is a feature that allows one token to be exchanged for another. It is useful when you need to interact with a downstream service on behalf of a user or client, enabling delegation of authorization.

## 3. Inject auth0 access token to keycloak
### A. Enable Store Token Option
Keycloak provides the ability to store tokens from identity providers.
    a. Go to the Keycloak Admin Console.
    b. Navigate to Identity Providers > Auth0.
    c. Enable the Store Token toggle.
        This ensures that Keycloak stores the Auth0 access token after the user authenticates with Auth0.
### B. Add a Protocol Mapper for the Auth0 Token
    To include the Auth0 token in the Keycloak access token (JWT), create a protocol mapper.
    a. Go to Clients in the Keycloak Admin Console.
    b. Select the client for which you want to include the Auth0 token.
    c. Navigate to the Mappers tab and add a new mapper:
        *Name: auth0_access_token
        *Mapper Type: User Session Note
        *Session Note: external_access_token
        *Token Claim Name: auth0_token
        *Claim JSON Type: String
        *Add to ID Token: Enabled (optional)
        *Add to Access Token: Enabled
        *Add to Userinfo: Enabled

### This will add the Auth0 token as a claim in the Keycloak tokens (ID Token or Access Token).
Example response
```{
"access_token": "eyJhbGciOiJIUzI1...",
"id_token": "eyJhbGciOiJIUzI1...",
"auth0_token": "eyJhbGciOiJIUzI1...",   // If added as a custom claim
"expires_in": 300,
"refresh_token": "eyJhbGciOiJIUzI1...",
"token_type": "bearer"
}
```


