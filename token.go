package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/exp/rand"
)

// Generate a random code verifier
func generateCodeVerifier() string {
	rand.Seed(uint64(time.Now().UnixNano()))
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// Generate the SHA256-based code challenge
func generateCodeChallenge(verifier string) string {
	sha := sha256.New()
	sha.Write([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sha.Sum(nil))
	return challenge
}

// Fetch JWKS (JSON Web Key Set) to validate the ID token
func getJWKS(jwkurl string) (*JWK, error) {
	resp, err := http.Get(jwkurl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwk JWK
	if err := json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
		return nil, err
	}

	return &jwk, nil
}

// Extract RSA public key from JWKS by the token's "kid" (key ID)
func getRSAPublicKey(token *jwt.Token, jwk *JWK) (*rsa.PublicKey, error) {
	if kid, ok := token.Header["kid"].(string); ok {
		for _, key := range jwk.Keys {
			if key.KeyID == kid {
				if rsaKey, ok := key.Key.(*rsa.PublicKey); ok {
					return rsaKey, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("unable to find appropriate key")
}

// Parse and validate ID token
func validateToken(jwkUrl string, idToken string) (*jwt.Token, error) {
	// Fetch JWKS from Auth0
	jwks, err := getJWKS(jwkUrl)
	if err != nil {
		return nil, err
	}

	// Parse the ID token
	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Extract the RSA public key from the JWKS
		return getRSAPublicKey(token, jwks)
	})

	// Validate the token
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	return token, nil
}
