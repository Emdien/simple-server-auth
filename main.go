package main

import (
	"crypto/rand"
	"net/http"
	"log"
	"github.com/Emdien/simple-server-auth/server"
)

func main() {

	hmacSecret := make([]byte, 32)

	if _, err := rand.Read(hmacSecret); err != nil {
		panic(err)
	}


	srv := server.New(hmacSecret)
    log.Fatal(http.ListenAndServe(":8088", srv.Routes()))
	// 1. Define a server with the routes to auth and validate token

	// 2. Implement handlers

	// 3. Implement a function that leverages PAM to check with user and password if its valid
	// If its valid, register the user in memory with a struct with IP, User and a private token that together with the token of the session creates a valid session
	// this needs to be researched, its kinda like pub keys

	// Could also research JWT tokens
}
