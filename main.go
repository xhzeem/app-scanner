// main.go
package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/SiriusScan/app-scanner/internal/scan"
	"github.com/SiriusScan/go-api/sirius/slogger"
	"github.com/SiriusScan/go-api/sirius/store"
)

func main() {
	// Initialize LOG_LEVEL-aware structured logging from the SDK.
	slogger.Init()

	slog.Info("Scanner service starting")

	// Create a new KVStore.
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		slog.Error("Failed to create KV store", "error", err)
		os.Exit(1)
	}
	defer kvStore.Close()

	// Instantiate the scan tool factory.
	toolFactory := &scan.ScanToolFactory{}

	// Create the scan updater for KV store updates.
	scanUpdater := scan.NewScanUpdater(kvStore)

	// Create the scan manager.
	scanManager := scan.NewScanManager(kvStore, toolFactory, scanUpdater)

	// Begin listening for scan requests in a goroutine.
	go scanManager.ListenForScans()

	// Begin listening for cancel commands in a goroutine.
	go scanManager.ListenForCancelCommands()

	slog.Info("Scanner service running",
		"scan_queue", "scan",
		"control_queue", "scan_control",
	)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Wait for shutdown signal
	sig := <-sigChan
	slog.Info("Received shutdown signal, initiating graceful shutdown", "signal", sig)

	// Gracefully shut down the scan manager
	slog.Info("Shutting down scan manager")
	scanManager.Shutdown()

	slog.Info("Scanner service stopped gracefully")
}
