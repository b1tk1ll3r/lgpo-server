package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"gpo-distributor/internal/agent"
)

var version = "dev"

func main() {
	defaultConfig := filepath.Join(os.Getenv("ProgramData"), "GPO-Distributor", "agent.json")
	if runtime.GOOS != "windows" && os.Getenv("ProgramData") == "" {
		defaultConfig = "/etc/gpo-distributor/agent.json"
	}
	configFile := flag.String("config", defaultConfig, "agent configuration JSON")
	once := flag.Bool("once", false, "synchronize once and exit")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if runtime.GOOS != "windows" {
		log.Fatal("gpo-agent can apply policies only on Windows")
	}

	logger := log.New(os.Stdout, "gpo-agent ", log.LstdFlags|log.LUTC)
	cfg, err := agent.LoadConfig(*configFile)
	if err != nil {
		logger.Fatal(err)
	}
	runner, err := agent.New(cfg, version, logger)
	if err != nil {
		logger.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := runner.Run(ctx, *once); err != nil && err != context.Canceled {
		logger.Fatal(err)
	}
}
