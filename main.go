package main

import (
	"crypto/rand"
	"net/http"
	"log"
	"github.com/Emdien/simple-server-auth/server"
	"flag"
)

func main() {

	hmacSecret := make([]byte, 32)

	portPtr := flag.String("port", ":8088", "Server port it will be listening to")
	tokenDurationHour := flag.Int("hours", 1, "Duration of token in hours. Larger unit takes precedence. Does not sum.")
	tokenDurationMinutes := flag.Int("minutes", 0, "Duration of token in minutes. Larger unit takes precedence. Does not sum.")
	tokenDurationSeconds := flag.Int("seconds", 0, "Duration of token in seconds. Larger unit takes precedence. Dooes not sum.")
	secretPtr := flag.String("secret", "", "HMAC Secret to use in token creation. If none passed, it will create one in runtime. (Volatile)")
	verbosePtr := flag.Bool("verbose", false, "")

	if _, err := rand.Read(hmacSecret); err != nil {
		panic(err)
	}


	srv := server.NewServer(hmacSecret)
    log.Fatal(http.ListenAndServe(":8088", srv.Routes()))

}
