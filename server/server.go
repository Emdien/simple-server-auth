package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"github.com/Emdien/simple-server-auth/auth"
)


type HMACAuthServer struct {
	hmacSecret []byte
}

type AuthRequest struct {
	Username string
	Password string // ALWAYS use HTTPS. Otherwise this is plain text.
}


func NewServer(hmacSecret []byte) *HMACAuthServer {
	return &HMACAuthServer{hmacSecret: hmacSecret}
}

func (s *HMACAuthServer) AuthHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Read body with Username, HashedPwd 

	var authRq AuthRequest

	if err := json.NewDecoder(r.Body).Decode(&authRq); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	// 2. Call PAM functions to auth

	// TODO
	_, err := auth.CheckCredentials("auth-service",authRq.Username, authRq.Password)

	if err != nil {
		msg := fmt.Sprintf("Invalid credentials: %s", err.Error())
		http.Error(w, msg, http.StatusUnauthorized)
		return
	}

	// 3. If auth successful, create a token

	token, err := createToken(s.hmacSecret, authRq.Username, "localhost", time.Hour * 6)

	if err != nil {
		msg := fmt.Sprintf("Error during token creation: %s", err.Error())
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}


	// 4. Return token string
	w.WriteHeader(http.StatusOK) //		This is default behaviour. But being explicit about it.
	fmt.Fprintln(w, token)

}

func (s * HMACAuthServer) ValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Grab token string from header

	authToken := r.Header.Get("Authorization")

	if authToken == "" {
		http.Error(w, "No Authorization header found", http.StatusUnauthorized)
		return
	}

	// 2. Call validateToken function

	_, expired, err := validateTokenString(authToken, s.hmacSecret)

	if err != nil {
		msg := fmt.Sprintf("Token validation failed with error: %s", err.Error())
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	if expired {
		http.Error(w, "Token is expired. Generate a new one", http.StatusUnauthorized)
		return
	}
	
	w.WriteHeader(http.StatusOK)

}

// Need to define the following handlers

// 1. An auth handler that receives as a body the user and password
// The password should be hashed and salted or something, should not be plain --- NVM, HTTPS duh.
// This is the core handler of this service. It will rely on PAM functions to perform the auth.

// 2. A token validator. Receives a token string in the body or in an auth header (check for both, prioritize the header)

// 3. A token refresher? Will see


// The idea is that any internal application will be hidden behind an NGINX or similar that will autoperform auth checks.
// Apache -> NGINX -> Application (might be another NGINX depending on the Apps architecture) in our server
// It might be a few too many redirections/proxies, however I don't wanna touch the public facing Apache
// Another option would be to modify the NGINX or whichever API Gateway the different apps are using to point to this service automatically
// But uhhhhhh will see.


// Might be interesting to look into Traefik to see how it works, since it seems like it integrates well with Docker.

// Routes go here.
func (s *HMACAuthServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth", s.AuthHandler)
	mux.HandleFunc("GET /validate", s.ValidateTokenHandler)
	return mux
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



