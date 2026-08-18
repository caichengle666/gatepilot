package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caichengle666/gatepilot/internal/store"
	"github.com/caichengle666/gatepilot/internal/vpn"
)

func TestIsLocalProxyEnvironmentFailure(t *testing.T) {
	tests := []struct {
		message string
		want    bool
	}{
		{message: `出口连接测试失败: Get "https://api.ip.sb/ip": Bad Gateway`, want: false},
		{message: "OpenVPN Windows adapter is not ready", want: true},
		{message: "i/o timeout", want: false},
		{message: "AUTH_FAILED", want: false},
	}
	for _, test := range tests {
		if got := isLocalProxyEnvironmentFailure(test.message); got != test.want {
			t.Fatalf("isLocalProxyEnvironmentFailure(%q) = %v, want %v", test.message, got, test.want)
		}
	}
}

func TestMaintainRefreshesNodesAfterAutomaticConnectionFailures(t *testing.T) {
	refreshes := 0
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		refreshes++
		http.Error(writer, "temporary failure", http.StatusBadGateway)
	}))
	defer api.Close()

	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.APIURL = api.URL
	config.DisableBackground = true
	config.InitialTestLimit = 0
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	application.Nodes = []store.Node{
		{ID: "node-1", ProbeStatus: "available", ConfigFile: "node-1.ovpn"},
		{ID: "node-2", ProbeStatus: "available", ConfigFile: "node-2.ovpn"},
		{ID: "node-3", ProbeStatus: "available", ConfigFile: "node-3.ovpn"},
	}
	application.Config.TargetValidNodes = 3
	webApp := NewApplication(application, vpn.NewController(application))

	if _, err := webApp.maintainLocked(context.Background(), false); err == nil {
		t.Fatal("expected automatic connection to fail")
	}
	if refreshes != 1 {
		t.Fatalf("node API refreshes = %d, want 1 after three failed connections", refreshes)
	}
}

func TestMaintainDoesNotRefreshAfterManualDisconnect(t *testing.T) {
	refreshes := 0
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		refreshes++
		http.Error(writer, "unexpected refresh", http.StatusBadGateway)
	}))
	defer api.Close()

	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.APIURL = api.URL
	config.DisableBackground = true
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	application.Config.InitialTestLimit = 0
	application.Nodes = []store.Node{{ID: "node-1", ProbeStatus: "available", ConfigFile: "node-1.ovpn"}}
	application.SetConnectionEnabled(false)
	webApp := NewApplication(application, vpn.NewController(application))

	if _, err := webApp.maintainLocked(context.Background(), false); err != nil {
		t.Fatalf("manual disconnect maintenance failed: %v", err)
	}
	if refreshes != 0 {
		t.Fatalf("node API refreshes = %d after manual disconnect, want 0", refreshes)
	}
}

func TestProxyHealthFailureThreshold(t *testing.T) {
	application := &Application{}
	if got := application.recordProxyHealth(false); got != 1 {
		t.Fatalf("first proxy failure count = %d, want 1", got)
	}
	if got := application.recordProxyHealth(false); got != 2 {
		t.Fatalf("second proxy failure count = %d, want 2", got)
	}
	if got := application.recordProxyHealth(false); got != maxProxyHealthFailures {
		t.Fatalf("threshold proxy failure count = %d, want %d", got, maxProxyHealthFailures)
	}
	if got := application.recordProxyHealth(true); got != 0 {
		t.Fatalf("successful proxy check count = %d, want 0", got)
	}
}

func TestFailureRefreshBackoff(t *testing.T) {
	application := &Application{}
	if !application.allowFailureRefresh() {
		t.Fatal("first failure refresh should be allowed")
	}
	if application.allowFailureRefresh() {
		t.Fatal("failure refresh should be throttled during backoff")
	}
	application.failureRefreshMu.Lock()
	application.lastFailureRefresh = application.lastFailureRefresh.Add(-failureRefreshBackoff)
	application.failureRefreshMu.Unlock()
	if !application.allowFailureRefresh() {
		t.Fatal("failure refresh should be allowed after backoff")
	}
}
