package main

import (
	"log"
	"net/http"
	"os"

	"github.com/kaitou-1412/auth-service/internal/app"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		log.Fatal("PORT is not found in the environment variables")
	}

	r := app.NewRouter()

	srv := &http.Server{
		Handler: r,
		Addr:    ":" + port,
	}

	log.Printf("Starting server on port %s", port)
	log.Fatal(srv.ListenAndServe())
}
