package main

import (
	"net/http"
	"time"
	"github.com/golang-jwt/jwt/v5"
)


type HMACAuthServer struct {
	hmacSecret []byte
}



// Need to define the following handlers

// 1. An auth handler that receives as a body the user and password
// The password should be hashed and salted or something, should not be plain.
// This is the core handler of this service. It will rely on PAM functions to perform the auth.

// 2. A token validator. Receives a token string in the body or in an auth header (check for both, prioritize the header)

// 3. A token refresher? Will see


// The idea is that any internal application will be hidden behind an NGINX or similar that will autoperform auth checks.
// Apache -> NGINX -> Application (might be another NGINX depending on the Apps architecture) in our server
// It might be a few too many redirections/proxies, however I don't wanna touch the public facing Apache
// Another option would be to modify the NGINX or whichever API Gateway the different apps are using to point to this service automatically
// But uhhhhhh will see.


// Might be interesting to look into Traefik to see how it works, since it seems like it integrates well with Docker.

// A pointer to request to not copy the struct on call
func authHandler(w http.ResponseWriter, r *http.Request) {

	// 1. Read body with Username, HashedPwd 

	// 2. Decode password -> It has to be valid. If not valid somehow, return error. For a simple use case, unhashed.

	// 3. Call PAM functions to auth

	// 4. If auth successful, create a token

	// 5. Return token string


}

func validateTokenHandler(w http.ResponseWriter, r *http.Request) {

	// 1. Grab token string from header

	authToken := r.Header.Get("Authorization")

	if authToken == "" {
		http.Error(w, "No Authorization header found", http.StatusUnauthorized)
		return
	}

	// 2. Call validateToken function

	valid, expired, err = validateTokenString()

	// 3. Handle error. Otherwise, 200 OK


}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {

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



