package main

import (
	"path/filepath"
	"testing"
)

func TestNewStoreResetsTransientRuntimeState(t *testing.T) {
	config := loadAppConfig()
	config.DataDir = t.TempDir()
	staleState := runtimeState{
		Status:              "connected",
		Message:             "stale",
		ActiveNodeID:        "JP_test",
		ActiveOpenVPNNodeID: "JP_test",
		ActiveNodeLatency:   "10 ms",
		IsConnecting:        true,
		MaintenanceRunning:  true,
		LastFetchStatus:     "ok",
		ProxyOK:             true,
		ProxyIP:             "203.0.113.1",
		ProxyLatencyMS:      10,
		ProxyError:          "stale",
	}
	if err := writeJSON(filepath.Join(config.DataDir, "state.json"), staleState); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(config.DataDir, "nodes.json"), []node{{ID: "JP_test", Active: true}}); err != nil {
		t.Fatal(err)
	}

	application, err := newStore(config)
	if err != nil {
		t.Fatal(err)
	}
	_, state, nodes := application.snapshot()
	if state.Status != "disconnected" || state.Message != "尚未连接 VPN" || state.ActiveNodeID != "" || state.ActiveOpenVPNNodeID != "" {
		t.Fatalf("transient connection state was not reset: %+v", state)
	}
	if state.ActiveNodeLatency != "无活动连接" || state.IsConnecting || state.MaintenanceRunning || state.ProxyOK || state.ProxyIP != "-" || state.ProxyLatencyMS != 0 || state.ProxyError != "" {
		t.Fatalf("transient runtime fields were not reset: %+v", state)
	}
	if state.LastFetchStatus != "ok" {
		t.Fatalf("persistent status was lost: %+v", state)
	}
	if len(nodes) != 1 || nodes[0].Active {
		t.Fatalf("persisted active node was not reset: %+v", nodes)
	}
}
