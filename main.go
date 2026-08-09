package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {

	hmacSecret := make([]byte, 32)

	if _, err := rand.Read(hmacSecret); err != nil {
		panic(err)
	}

	token, err := createToken(hmacSecret, "Test", "localhost", time.Hour*6)

	if err != nil {
		panic(err)
	}

	valid, _, err := validateTokenString(token, hmacSecret)
	fmt.Println(valid)
	// 1. Define a server with the routes to auth and validate token

	// 2. Implement handlers

	// 3. Implement a function that leverages PAM to check with user and password if its valid
	// If its valid, register the user in memory with a struct with IP, User and a private token that together with the token of the session creates a valid session
	// this needs to be researched, its kinda like pub keys

	// Could also research JWT tokens
}

func createToken(
	hmacSecret []byte,
	sub string,
	iss string,
	exp time.Duration,
) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"iss": iss,
		"exp": time.Now().Add(exp).Unix(),
		"iat": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	tokenString, err := token.SignedString(hmacSecret)

	if err != nil {
		return "", err
	}

	return tokenString, err

}

// Valid - Expired - Error
func validateTokenString(tokenString string, hmacSecret []byte) (bool, bool, error) {

	// Get expiration date at the beginning of function call. It should not matter but its small enough.
	timeNow := time.Now()

	// Currently we ignore the JWT token obtained from parsing it.

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return hmacSecret, nil // Should this be different?
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil {
		return false, false, err
	}

	// We check its claims. In particular, check expiry date.
	// In particular we check for expiration. If expired, not valid.
	// Should return some sort of special case for this.

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if expFloat, ok := claims["exp"].(float64); ok {
			expiration := time.Unix(int64(expFloat), 0)
			if timeNow.After(expiration) {
				// Expired token
				return false, true, nil
			}
			// Valid token
			return true, false, nil
		}
		// Wrong exp claim field - Altered token?
		return false, false, fmt.Errorf("invalid exp claim type")
	}

	// Invalid token.
	return false, false, fmt.Errorf("invalid token claims")

}
