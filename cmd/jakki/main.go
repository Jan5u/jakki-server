package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Jan5u/jakki-server/database"
	"github.com/Jan5u/jakki-server/server"
)

const addr = "0.0.0.0:7777"

func main() {
	// init database
	dataDir := server.GetDataDir()
	db, err := database.New(dataDir)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// init server
	srv := server.NewServer(addr, db)
	if err := srv.LoadChannels(); err != nil {
		_ = db.Close()
		log.Fatalf("Failed to load channels: %v", err)
	}

	// run server
	go func() {
		if err := srv.RunServer(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()
	log.Printf("Listening on %s\n", addr)

	// wait for sigterm
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	if err := srv.Stop(); err != nil {
		log.Printf("Error stopping server: %v", err)
	}

	log.Println("Closing database...")
	if err := db.Close(); err != nil {
		log.Printf("Error closing database: %v", err)
	}
}
