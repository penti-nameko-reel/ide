package main

import (
	"log"
	"net/http"
	"os"

	"idp/internal/config"
	"idp/internal/db"
	"idp/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil { log.Fatal(err) }
	store, err := db.Open(cfg.DatabaseURL)
	if err != nil { log.Fatal(err) }
	defer store.Close()
	if err := store.EnsureAdmin(cfg.AdminEmail, cfg.AdminPassword); err != nil { log.Fatal(err) }
	srv, err := server.New(cfg, store)
	if err != nil { log.Fatal(err) }
	log.Printf("idp listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.Handler()); err != nil { log.Printf("server stopped: %v", err); os.Exit(1) }
}
