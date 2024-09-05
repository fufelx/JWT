package main

import (
	"JWT/pkg/api"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/token", api.Token)
	http.HandleFunc("/refresh", api.Refresh)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
