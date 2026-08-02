package store

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadAppConfigDefaults(t *testing.T) {
	for _, name := range []string{
		"OPENVPN_AUTH_USER", "OPENVPN_AUTH_PASS", "LOCAL_PROXY_HOST", "LOCAL_PROXY_PORT",
		"LOCAL_PROXY_MAX_CONNECTIONS", "UI_HOST", "UI_PORT", "FETCH_INTERVAL_SECONDS",
		"RECONNECT_INTERVAL_SECONDS", "OPENVPN_TEST_TIMEOUT_SECONDS", "TARGET_VALID_NODES",
		"MAX_SCAN_ROWS", "INVALID_BACKOFF_SECONDS", "MANUAL_TEST_NODE_LIMIT",
		"INITIAL_CONNECT_TEST_LIMIT", "DISABLE_BACKGROUND_FETCH",
	} {
		t.Setenv(name, "")
	}

	config := LoadAppConfig()
	if config.OpenVPNUser != "vpn" || config.OpenVPNPassword != "vpn" {
		t.Fatalf("unexpected OpenVPN credentials: %q/%q", config.OpenVPNUser, config.OpenVPNPassword)
	}
	if config.ProxyHost != "127.0.0.1" || config.ProxyPort != 7928 || config.ProxyMaxConnections != 256 {
		t.Fatalf("unexpected proxy defaults: %+v", config)
	}
	if config.UIHost != "::" || config.UIPort != 8787 {
		t.Fatalf("unexpected UI defaults: %+v", config)
	}
	if config.FetchInterval != 1260*time.Second || config.ReconnectInterval != 15*time.Second || config.OpenVPNTimeout != 35*time.Second {
		t.Fatalf("unexpected interval defaults: %+v", config)
	}
	if config.TargetValidNodes != 3 || config.MaxScanRows != 300 || config.InvalidBackoff != 1800*time.Second {
		t.Fatalf("unexpected node defaults: %+v", config)
	}
	if config.ManualTestNodeLimit != 5 || config.InitialTestLimit != 10 || config.DisableBackground {
		t.Fatalf("unexpected maintenance defaults: %+v", config)
	}
}

func TestNewStoreResetsTransientRuntimeState(t *testing.T) {
	config := LoadAppConfig()
	config.DataDir = t.TempDir()
	staleState := RuntimeState{
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
	if err := writeJSON(filepath.Join(config.DataDir, "nodes.json"), []Node{{ID: "JP_test", Active: true}}); err != nil {
		t.Fatal(err)
	}

	application, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ui, state, nodes := application.Snapshot()
	if ui.SpeedTestURL != DefaultSpeedTestURL {
		t.Fatalf("speed test URL = %q, want %q", ui.SpeedTestURL, DefaultSpeedTestURL)
	}
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

func TestNormalizeSpeedTestURL(t *testing.T) {
	if got, err := NormalizeSpeedTestURL(""); err != nil || got != DefaultSpeedTestURL {
		t.Fatalf("default speed test URL = %q, err=%v", got, err)
	}
	if got, err := NormalizeSpeedTestURL(" https://example.com/download?bytes=10 "); err != nil || got != "https://example.com/download?bytes=10" {
		t.Fatalf("normalized speed test URL = %q, err=%v", got, err)
	}
	for _, value := range []string{"ftp://example.com/file", "/relative/path", "https:///missing-host"} {
		if _, err := NormalizeSpeedTestURL(value); err == nil {
			t.Fatalf("expected invalid speed test URL %q", value)
		}
	}
}

func TestParseVPNGateCSV(t *testing.T) {
	profile := "client\nproto udp\nremote 203.0.113.8 1194\n"
	csvText := "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,TotalUsers,TotalTraffic,LogType,Message,OpenVPN_ConfigData_Base64\n" +
		"vpn.example,203.0.113.8,100,42,9000000,Japan,JP,5,10,1000,2weeks,ok," + base64.StdEncoding.EncodeToString([]byte(profile)) + "\n*\n"
	nodes, err := parseVPNGateCSV(strings.NewReader(csvText), 10)
	if err != nil {
		t.Fatalf("parseVPNGateCSV returned error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}
	got := nodes[0]
	if got.Country != "日本" || got.RemoteHost != "203.0.113.8" || got.RemotePort != 1194 || got.Protocol != "udp" {
		t.Fatalf("unexpected node: %+v", got)
	}
}

func TestFetchAttemptUsesUpstreamProxy(t *testing.T) {
	profile := "client\nproto tcp\nremote 203.0.113.8 443\n"
	csvText := "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,TotalUsers,TotalTraffic,LogType,Message,OpenVPN_ConfigData_Base64\n" +
		"vpn.example,203.0.113.8,100,42,9000000,Japan,JP,5,10,1000,2weeks,ok," + base64.StdEncoding.EncodeToString([]byte(profile)) + "\n*\n"
	var called atomic.Bool
	proxyServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called.Store(true)
		_, _ = writer.Write([]byte(csvText))
	}))
	defer proxyServer.Close()

	application := &Store{
		Config: AppConfig{MaxScanRows: 10},
		UI:     UIConfig{UpstreamProxy: proxyServer.URL},
	}
	nodes, err := application.fetchAttempt(context.Background(), "http://vpngate.invalid/api/iphone/", false)
	if err != nil {
		t.Fatalf("fetchAttempt returned error: %v", err)
	}
	if !called.Load() {
		t.Fatal("upstream proxy was not used")
	}
	if len(nodes) != 1 || nodes[0].HostName != "vpn.example" {
		t.Fatalf("unexpected nodes: %+v", nodes)
	}
}

func TestFavoriteRoutingWithoutFallback(t *testing.T) {
	application := &Store{
		UI:    UIConfig{RoutingMode: "favorites", FavoriteNodeIDs: []string{"favorite"}},
		Nodes: []Node{{ID: "favorite", ProbeStatus: "available"}, {ID: "other", ProbeStatus: "available"}},
	}
	candidates := application.Candidates()
	if len(candidates) != 1 || candidates[0].ID != "favorite" {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
}

func TestCandidatesPreferUDPWithinSameProbeStatus(t *testing.T) {
	application := &Store{
		UI: UIConfig{},
		Nodes: []Node{
			{ID: "tcp", Protocol: "tcp", ProbeStatus: "available", LatencyMS: 10, Score: 100},
			{ID: "udp", Protocol: "udp", ProbeStatus: "available", LatencyMS: 100, Score: 10},
		},
	}
	candidates := application.Candidates()
	if len(candidates) != 2 || candidates[0].ID != "udp" {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
}

func TestCandidatesKeepAvailableTCPBeforeUnavailableUDP(t *testing.T) {
	application := &Store{
		UI: UIConfig{},
		Nodes: []Node{
			{ID: "udp", Protocol: "udp", ProbeStatus: "unavailable"},
			{ID: "tcp", Protocol: "tcp", ProbeStatus: "available"},
		},
	}
	candidates := application.Candidates()
	if len(candidates) != 2 || candidates[0].ID != "tcp" {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
}
