package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gpo-distributor/internal/httpapi"
	"gpo-distributor/internal/store"
)

var version = "dev"

func main() {
	listen := flag.String("listen", env("GPO_SERVER_LISTEN", ":8443"), "listen address")
	dataDir := flag.String("data", env("GPO_SERVER_DATA", "./data"), "data directory")
	adminToken := flag.String("admin-token", os.Getenv("GPO_SERVER_ADMIN_TOKEN"), "admin bearer token")
	clientToken := flag.String("client-token", os.Getenv("GPO_SERVER_CLIENT_TOKEN"), "client bearer token")
	signingKey := flag.String("signing-key", os.Getenv("GPO_SERVER_SIGNING_KEY"), "manifest HMAC signing key")
	tlsCert := flag.String("tls-cert", os.Getenv("GPO_SERVER_TLS_CERT"), "TLS certificate path")
	tlsKey := flag.String("tls-key", os.Getenv("GPO_SERVER_TLS_KEY"), "TLS private key path")
	maxUpload := flag.Int64("max-upload", 512<<20, "maximum upload size in bytes")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := log.New(os.Stdout, "gpo-server ", log.LstdFlags|log.LUTC)
	st, err := store.Open(*dataDir)
	if err != nil {
		logger.Fatal(err)
	}
	api, err := httpapi.New(st, httpapi.Config{
		AdminToken: *adminToken, ClientToken: *clientToken, SigningKey: *signingKey,
		ServerVersion: version, MaxUpload: *maxUpload, Logger: logger,
	})
	if err != nil {
		logger.Fatal(err)
	}

	srv := &http.Server{
		Addr: *listen, Handler: api.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Minute,
		WriteTimeout: 15 * time.Minute, IdleTimeout: 2 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		logger.Printf("version=%s listen=%s data=%s", version, *listen, *dataDir)
		var err error
		if *tlsCert != "" || *tlsKey != "" {
			if *tlsCert == "" || *tlsKey == "" {
				logger.Fatal("both -tls-cert and -tls-key are required")
			}
			err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			logger.Printf("WARNING: TLS disabled; use only behind a TLS reverse proxy or in a test network")
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Printf("shutdown: %v", err)
	}
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
