package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Emdien/simple-server-auth/auth"
	"github.com/golang-jwt/jwt/v5"
)


type HMACAuthServer struct {
	hmacSecret []byte
	tokenDurationHour int
	tokenDurationMinutes int
	tokenDurationSeconds int
	refreshWindow int
	sessionHours int
	sessionMinutes int
	sessionSeconds int
}

type AuthRequest struct {
	Username string
	Password string // ALWAYS use HTTPS. Otherwise this is plain text.
}


func NewServer(hmacSecret []byte, tokenDurationHour, tokenDurationMinutes, tokenDurationSeconds, sessionHours, sessionMinutes, sessionSeconds, refreshWindow int ) *HMACAuthServer {
	log.Println("Starting server")
	return &HMACAuthServer{
		hmacSecret: hmacSecret,
		tokenDurationHour: tokenDurationHour,
		tokenDurationMinutes: tokenDurationMinutes,
		tokenDurationSeconds: tokenDurationSeconds,
		refreshWindow: refreshWindow,
		sessionHours: sessionHours,
		sessionMinutes: sessionMinutes,
		sessionSeconds: sessionSeconds,
	}
}

func (s *HMACAuthServer) AuthHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Read body with Username, HashedPwd 
	log.Println("Auth request received")
	var authRq AuthRequest

	if err := json.NewDecoder(r.Body).Decode(&authRq); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		log.Println("[ERROR] Unable to parse body of request")
		return
	}

	log.Printf("Username request: %s\n", authRq.Username)

	// 2. Call PAM functions to auth
	_, err := auth.CheckCredentials("auth-service",authRq.Username, authRq.Password)

	if err != nil {
		msg := fmt.Sprintf("Invalid credentials: %s", err.Error())
		http.Error(w, msg, http.StatusUnauthorized)
		return
	}

	log.Println("PAM auth successful")

	// 3. If auth successful, create a token
	exp := time.Duration(s.tokenDurationSeconds)*time.Second+time.Duration(s.tokenDurationMinutes)*time.Minute+time.Duration(s.tokenDurationHour)*time.Hour
	token, err := createToken(s.hmacSecret, authRq.Username, "localhost", exp)


	if err != nil {
		msg := fmt.Sprintf("Error during token creation: %s", err.Error())
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}


	// 4. Return token string
	w.WriteHeader(http.StatusOK) //		This is default behaviour. But being explicit about it.
	attachToken(w, token, exp)
	fmt.Fprintln(w, token)

	log.Println("Auth successful")

}

func (s * HMACAuthServer) ValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Grab token string from header
	log.Print("Validation request received")
	authToken := r.Header.Get("Authorization")

	if authToken == "" {
		http.Error(w, "No Authorization header found", http.StatusUnauthorized)
		return
	}

	// 2. Call validateToken function

	_, expired, err := validateTokenString(s, w, authToken, s.hmacSecret)

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
	log.Println("Token validated successfully")

}


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


	iat := time.Now()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"iss": iss,
		"exp": iat.Add(exp).Unix(),
		"iat": iat.Unix(),
		"og_iat": iat.Unix(),
	})

	tokenString, err := token.SignedString(hmacSecret)

	if err != nil {
		return "", err
	}

	return tokenString, err

}

// Valid - Expired - Error
func validateTokenString(s *HMACAuthServer, w http.ResponseWriter, tokenString string, hmacSecret []byte) (bool, bool, error) {

	// Get expiration date at the beginning of function call. It should not matter but its small enough.
	timeNow := time.Now()

	log.Println("Parsing token")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return hmacSecret, nil // Should this be different?
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil {


		switch {
		case errors.Is(err, jwt.ErrTokenMalformed) || errors.Is(err, jwt.ErrSignatureInvalid):
			return false, false, err

		case errors.Is(err, jwt.ErrTokenExpired):
			return false, true, nil
		}

	}

	// We check its claims.

	if claims, ok := token.Claims.(jwt.MapClaims); ok {

		log.Println("Checking claims")
		if expFloat, ok := claims["exp"].(float64); ok {
			expiration := time.Unix(int64(expFloat), 0)

			// Expiration check is performed at jwt.Parse

			/* log.Printf("Expiration: %s\n", expiration.String())
			if timeNow.After(expiration) {
				// Expired token
				log.Println("Expired")
				return false, true, nil
			} */

			// Check for session duration, regardless of expiry
			if ogIatFloat, ok := claims["og_iat"].(float64); ok {
				sessionExp := time.Unix(int64(ogIatFloat), 0).Add(time.Duration(s.sessionSeconds)*time.Second+time.Duration(s.sessionMinutes)*time.Minute+time.Duration(s.sessionHours)*time.Hour)

				if timeNow.After(sessionExp) {

					log.Println("Session expired")
					return false, true, nil
				}
			}

			// Check for session. The goal is to refresh a token before it expires
			// 1. Tokens have a 6h session limit by default ( add a server flag for it)
			// 2. If a token is within the refresh window (a value defined with a flag, by default 5 minutes before exp)
			// then refresh the token, creating a new token and updating iat and exp field, while maintaining og_iat etc
			// 3. The token should be added in multiple places. As a header, as a cookie
			// and in the case of /auth, in the body too.
			rWindowAfter := expiration.Add(-time.Duration(s.refreshWindow)*time.Minute)

			// I have checked that the token is neither expired nor outside of session
			// I can now check if the token is in the refresh window.
			// Need to refresh
			if timeNow.After(rWindowAfter) {
				
				iat := time.Now()
				exp := time.Duration(s.tokenDurationSeconds)*time.Second+time.Duration(s.tokenDurationMinutes)*time.Minute+time.Duration(s.tokenDurationHour)*time.Hour

				refresh_token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"sub": claims["sub"],
					"iss": claims["iss"],
					"exp": iat.Add(exp).Unix(),
					"iat": iat.Unix(),
					"og_iat": claims["og_iat"],
				})


				tokenString, err := refresh_token.SignedString(hmacSecret)

				if err != nil {
					return false, false, err
				}

				attachToken(w, tokenString, exp)


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


func attachToken(w http.ResponseWriter, token string, exp time.Duration)  {

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Domain:   "localhost",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(exp),
	})
}



