package main

import (
	"crypto/rand"
	"net/http"
	"log"
	"github.com/Emdien/simple-server-auth/server"
	"flag"
)

func main() {

	
	portPtr := flag.String("port", ":8088", "Server port it will be listening to. Format is :<port>")
	tokenDurationHours := flag.Int("tokenH", 0, "Duration of token in hours")
	tokenDurationMinutes := flag.Int("tokenM", 20, "Duration of token in minutes.")
	tokenDurationSeconds := flag.Int("tokenS", 0, "Duration of token in seconds.")
	secretPtr := flag.String("secret", "", "HMAC Secret to use in token creation. If none passed, it will create one in runtime. (Volatile)")
	refreshWindow := flag.Int("refresh", 5, "Duration in minutes of the refresh window where a token can be refreshed with a new one before expiring.")
	sessionHours := flag.Int("sessionH", 6, "Duration in hours of the session duration, in which a token will be deemed invalid regardless of expiration, and cannot be refreshed.")
	sessionMinutes := flag.Int("sessionM", 6, "Duration in minutes of the session duration, in which a token will be deemed invalid regardless of expiration, and cannot be refreshed.")
	sessionSeconds := flag.Int("sessionS", 6, "Duration in seconds of the session duration, in which a token will be deemed invalid regardless of expiration, and cannot be refreshed.")
	
	flag.Parse()

	var hmacSecret []byte
	if *secretPtr != "" {
		hmacSecret = []byte(*secretPtr)
	} else {
		hmacSecret = make([]byte, 32)
		if _, err := rand.Read(hmacSecret); err != nil {
			panic(err)
		}
	}

	srv := server.NewServer(hmacSecret, *tokenDurationHours, *tokenDurationMinutes, *tokenDurationSeconds, *sessionHours, *sessionMinutes, *sessionSeconds, *refreshWindow)
    log.Fatal(http.ListenAndServe(*portPtr, srv.Routes()))

}
