package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/joho/godotenv"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

var (
	auth0Config       *oauth2.Config
	sentinelConfig    *oauth2.Config
	auth0JwksURL      string
	auth0Audience     string
	sentinelJwksURL   string
	sentinelLogoutURL string

	oauthStateString     = "random-state-string" // Random state string to prevent CSRF attacks
	codeVerifier         string
	sentinelAccessToken  string
	sentinelRefreshToken string
	sentinelIdToken      string

	auth0AccessToken  string
	auth0RefreshToken string
	auth0IdToken      string
)

func init() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Auth0 OAuth2 configuration
	auth0Config = &oauth2.Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),     // Set this in your environment variables
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"), // Set this in your environment variables
		RedirectURL:  os.Getenv("AUTH0_REDIRECT_URL"),  // The callback URL registered with Auth0
		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("AUTH0_AUTH_URL"),
			TokenURL: os.Getenv("AUTH0_TOKEN_URL"),
		},
		Scopes: []string{"openid", "profile", "email", "offline_access"}, // Scopes, including openid for authentication
	}

	auth0JwksURL = os.Getenv("AUTH0_JWKS_URL")
	auth0Audience = os.Getenv("AUTH0_AUDIENCE")
	sentinelLogoutURL = os.Getenv("SENTINEL_LOGOUT_URL")

	// SENTINEL OAuth2 configuration
	sentinelConfig = &oauth2.Config{
		ClientID:     os.Getenv("SENTINEL_CLIENT_ID"),     // Set this in your environment variables
		ClientSecret: os.Getenv("SENTINEL_CLIENT_SECRET"), // Set this in your environment variables
		RedirectURL:  os.Getenv("SENTINEL_REDIRECT_URL"),  // The callback URL registered with Sentinel
		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("SENTINEL_AUTH_URL"),
			TokenURL: os.Getenv("SENTINEL_TOKEN_URL"),
		},
		Scopes: []string{"openid", "profile", "email"}, // Scopes, including openid for authentication
	}

	sentinelJwksURL = os.Getenv("SENTINEL_JWKS_URL")

	// Generate code verifier (PKCE)
	codeVerifier = generateCodeVerifier()
}

// JWK (JSON Web Key) structure to hold the public keys for verifying tokens
type JWK struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

// Home page handler
func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `<html><body>
	<a href="/auth0login" style="font-size: 24px;">Log in with Auth0</a><br>
	<a href="/sentinellogin"  style="font-size: 24px;">Log in with Sentinel</a><br>
	<a href="/sentinellogout"  style="font-size: 24px;">Log out with Sentinel</a>
	</body></html>`
	fmt.Fprint(w, html)
}

// Main function to set up routes and start the server
func main() {
	// Set up the routes
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/sentinellogin", handleSentinelLogin)
	http.HandleFunc("/sentinellogout", handleSentinelLogout)
	http.HandleFunc("/auth0login", handleAuth0Login)
	http.HandleFunc("/sentinelcallback", handleSentinelCallback)
	http.HandleFunc("/auth0callback", handleAuth0Callback)

	url := "http://localhost:3000"
	err := browser.OpenURL(url)
	if err != nil {
		fmt.Println("Failed to open browser:", err)
	} else {
		fmt.Println("Browser opened successfully")
	}

	// Start the server on port 8080
	log.Println("Server is starting on port 3000...")
	log.Fatal(http.ListenAndServe("localhost:3000", nil))
}
