package main

import (
	"net"
	"testing"

	"github.com/caichengle666/gatepilot/internal/store"
)

func TestEnsureStartupPortsAvailableRejectsOccupiedWebPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	config := store.AppConfig{UIHost: "127.0.0.1", UIPort: port, ProxyHost: "127.0.0.1", ProxyPort: port + 1}
	if err := ensureStartupPortsAvailable(config); err == nil {
		t.Fatal("occupied Web port should reject startup")
	}
}
