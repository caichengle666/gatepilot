package web

import (
	"testing"
	"time"

	"github.com/caichengle666/gatepilot/internal/store"
	"github.com/caichengle666/gatepilot/internal/vpn"
)

func TestFailoverTunnelSchedulesRecoveryWhenNoBackupAvailable(t *testing.T) {
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApplication(application, vpn.NewController(application))

	previous := vpn.TunnelStatus{Device: "tun2", NodeID: "old-node", ProxyPort: 17930, PublishedProxyPort: 17930}
	app.failoverTunnel(previous, "测试原因")

	entry, found := app.nextTunnelRecovery()[previous.Device]
	if !found {
		t.Fatal("failover did not schedule tunnel recovery")
	}
	if entry.proxyPort != previous.ProxyPort {
		t.Fatalf("recovery proxy port = %d, want %d", entry.proxyPort, previous.ProxyPort)
	}
}

func TestTunnelRecoveryIsRescheduledAfterFailedAttempt(t *testing.T) {
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApplication(application, vpn.NewController(application))

	device := "tun1"
	proxyPort := 17929
	app.scheduleTunnelRecovery(device, proxyPort)
	entry, found := app.nextTunnelRecovery()[device]
	if !found {
		t.Fatal("recovery was not scheduled")
	}
	if entry.proxyPort != proxyPort {
		t.Fatalf("recovery proxy port = %d, want %d", entry.proxyPort, proxyPort)
	}

	// 候选列表为空时连接必定失败，恢复任务应被重新安排而不是丢弃。
	app.tunnelRecoveryMu.Lock()
	app.tunnelRecovery[device] = tunnelRecovery{proxyPort: proxyPort, nextTry: time.Now().Add(-time.Second)}
	app.tunnelRecoveryMu.Unlock()
	app.retryTunnelRecovery()

	entry, found = app.nextTunnelRecovery()[device]
	if !found {
		t.Fatal("recovery was dropped after a failed attempt")
	}
	if entry.proxyPort != proxyPort {
		t.Fatalf("rescheduled proxy port = %d, want %d", entry.proxyPort, proxyPort)
	}
	if entry.nextTry.Before(time.Now()) {
		t.Fatalf("rescheduled retry is still due: %+v", entry)
	}
}

func TestTunnelFailoverSkipsOtherConfigsOfFailedServer(t *testing.T) {
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	application.Nodes = []store.Node{
		{ID: "JP_udp", IP: "219.104.129.60", RemotePort: 44594, ProbeStatus: "available"},
		{ID: "JP_tcp", IP: "219.104.129.60", RemotePort: 443, ProbeStatus: "available"},
		{ID: "US_free", IP: "203.0.113.9", ProbeStatus: "available"},
	}
	app := NewApplication(application, vpn.NewController(application))
	failed, _ := application.NodeByID("JP_udp")
	skipIP := tunnelNodeIP(failed)
	for id, want := range map[string]bool{"JP_udp": true, "JP_tcp": true, "US_free": false} {
		candidate, _ := application.NodeByID(id)
		if got := app.skipTunnelCandidate(candidate, "tun3", "JP_udp", skipIP); got != want {
			t.Fatalf("skipTunnelCandidate(%s) = %v, want %v", id, got, want)
		}
	}
}
