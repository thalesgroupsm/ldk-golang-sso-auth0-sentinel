package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func handleSentinelLogin(w http.ResponseWriter, r *http.Request) {
	urlStr := sentinelConfig.AuthCodeURL(oauthStateString) // Generate the Sentinel consent page URL

	baseAuthURL, err := url.Parse(urlStr)
	if err != nil {
		log.Fatalf("Error parsing auth URL: %v", err)
	}

	// Add the PKCE parameters (code_challenge and code_challenge_method)
	query := baseAuthURL.Query()
	query.Set("code_challenge", generateCodeChallenge(codeVerifier))
	query.Set("code_challenge_method", "S256")
	baseAuthURL.RawQuery = query.Encode()

	urlStr = baseAuthURL.String()
	http.Redirect(w, r, urlStr, http.StatusTemporaryRedirect) // Redirect user to Sentinel consent page
}

func handleSentinelLogout(w http.ResponseWriter, r *http.Request) {
	// Prepare the request body
	data := url.Values{}
	data.Set("client_id", os.Getenv("SENTINEL_CLIENT_ID"))
	data.Set("refresh_token", sentinelRefreshToken)

	// Create the HTTP request
	req, err := http.NewRequest("POST", sentinelLogoutURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		fmt.Fprintf(w, "failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "failed to send request: %v", err)
		return
	}
	defer resp.Body.Close()

	// Read and log the response
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		fmt.Fprintf(w, "failed to logout: %s", string(body))
		return
	}

	fmt.Fprintf(w, "Logout successful:%s", string(body))
}

func handleSentinelCallback(w http.ResponseWriter, r *http.Request) {
	// Validate the state parameter to prevent CSRF attacks
	state := r.FormValue("state")
	if state != oauthStateString {
		log.Printf("invalid OAuth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Get the authorization code from the query string
	code := r.FormValue("code")

	// Exchange the authorization code for an access token
	token, err := sentinelConfig.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		log.Printf("failed to exchange token: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	sentinelAccessToken = token.AccessToken
	sentinelRefreshToken = token.Extra("refresh_token").(string)
	sentinelIdToken = token.Extra("id_token").(string)
	sentinelRefreshToken = token.Extra("refresh_token").(string)

	// Print the sentinel token details
	fmt.Printf("Sentinel Access Token: %s\n", sentinelAccessToken)
	fmt.Printf("Sentinel Refresh Token: %s\n", sentinelRefreshToken)
	fmt.Printf("Sentinel ID Token: %s\n", sentinelIdToken)

	handleAuth0Login(w, r)

	fmt.Printf("Sentinel Token Type: %s\n", token.TokenType)
	fmt.Printf("Sentinel Expiry: %s\n", token.Expiry)

	// Validate the ID token
	parsedToken, err := validateToken(sentinelJwksURL, token.AccessToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to validate ID token: %v", err), http.StatusInternalServerError)
		return
	}

	// Extract claims (including user ID)
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {

		fmt.Printf("Sentinel Token Claims:")
		for key, value := range claims {
			fmt.Printf("%s: %v\n", key, value)
		}
	} else {
		http.Error(w, "Invalid token", http.StatusInternalServerError)
	}
}
