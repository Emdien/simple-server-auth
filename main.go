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
	tokenDurationHour := flag.Int("hours", 0, "Duration of token in hours")
	tokenDurationMinutes := flag.Int("minutes", 20, "Duration of token in minutes.")
	tokenDurationSeconds := flag.Int("seconds", 0, "Duration of token in seconds.")
	secretPtr := flag.String("secret", "", "HMAC Secret to use in token creation. If none passed, it will create one in runtime. (Volatile)")

	
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

	srv := server.NewServer(hmacSecret, *tokenDurationHour, *tokenDurationMinutes, *tokenDurationSeconds)
    log.Fatal(http.ListenAndServe(*portPtr, srv.Routes()))

}
