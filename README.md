To configure Keycloak as an identity broker to federate authentication with Auth0 and obtain access tokens from both systems, there are the following options
1. SSO
This sample will demostrate how to go with sso with loopback way to let public application to get both access tokens from auth0 and keycloak.
2. Token exchange
Sample code
---------------------------------------------------------------------------------
import requests

def get_auth0_and_keycloak_tokens(auth0_auth_code):
    # Step 1: Exchange authorization code for Auth0 token
    auth0_token_response = requests.post(
        'https://your-auth0-domain/oauth/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth0_auth_code,
            'redirect_uri': 'https://yourapp.com/callback',
            'client_id': 'your_auth0_client_id',
            'client_secret': 'your_auth0_client_secret'
        }
    )
    auth0_access_token = auth0_token_response.json().get('access_token')

    # Step 2: Use Auth0's /userinfo endpoint to get Keycloak token if federated
    userinfo_response = requests.get(
        'https://your-auth0-domain/userinfo',
        headers={'Authorization': f'Bearer {auth0_access_token}'}
    )
    keycloak_token = userinfo_response.json().get('keycloak_token')  # Adjust based on custom mapping

    return auth0_access_token, keycloak_token
---------------------------------------------------------------------------------

3. Inject auth0 access token to keycloak

A. Enable Store Token Option
Keycloak provides the ability to store tokens from identity providers.

    a. Go to the Keycloak Admin Console.
    b. Navigate to Identity Providers > Auth0.
    c. Enable the Store Token toggle.
        This ensures that Keycloak stores the Auth0 access token after the user authenticates with Auth0.

B. Add a Protocol Mapper for the Auth0 Token

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

This will add the Auth0 token as a claim in the Keycloak tokens (ID Token or Access Token).

Example response
{
  "access_token": "eyJhbGciOiJIUzI1...",
  "id_token": "eyJhbGciOiJIUzI1...",
  "auth0_token": "eyJhbGciOiJIUzI1...",   // If added as a custom claim
  "expires_in": 300,
  "refresh_token": "eyJhbGciOiJIUzI1...",
  "token_type": "bearer"
}