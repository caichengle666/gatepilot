package web

import (
	"testing"
	"time"

	"github.com/caichengle666/gatepilot/internal/store"
	"github.com/caichengle666/gatepilot/internal/vpn"
)

func newSweepTestApp(t *testing.T, nodes []store.Node) *Application {
	t.Helper()
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	config.TargetValidNodes = 3
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	application.Nodes = nodes
	application.UI.ConnectionEnabled = false
	return NewApplication(application, vpn.NewController(application))
}

func TestSpareNodeTargetIsTwiceTunnelCount(t *testing.T) {
	app := newSweepTestApp(t, nil)
	if got := app.spareNodeTarget(); got != 3 {
		t.Fatalf("no tunnels: target = %d, want TargetValidNodes 3", got)
	}
	for _, device := range []string{"tun1", "tun2", "tun3", "tun4"} {
		app.scheduleTunnelRecovery(device, 17929)
	}
	if got := app.spareNodeTarget(); got != 8 {
		t.Fatalf("4 tunnels: target = %d, want 8", got)
	}
}

func TestPickSweepNodesPrefersPendingWhenShort(t *testing.T) {
	now := time.Now()
	app := newSweepTestApp(t, []store.Node{
		{ID: "fresh", IP: "198.51.100.1", ProbeStatus: "available", ProbedAt: now.Unix()},
		{ID: "failed", IP: "198.51.100.2", ProbeStatus: "unavailable", ProbedAt: now.Unix()},
		{ID: "cancelled", IP: "198.51.100.3", ProbeStatus: "unavailable", ProbeMessage: "后台检测已取消", ProbedAt: now.Unix()},
		{ID: "pending", IP: "198.51.100.4"},
		{ID: "stale", IP: "198.51.100.5", ProbeStatus: "available", ProbedAt: now.Add(-time.Hour).Unix()},
	})
	got := app.pickSweepNodes(now)
	if len(got) != 2 || got[0] != "cancelled" && got[0] != "pending" || got[1] != "cancelled" && got[1] != "pending" {
		t.Fatalf("picked %v, want cancelled and pending", got)
	}
}

func TestPickSweepNodesOnlyRechecksStaleWhenEnough(t *testing.T) {
	now := time.Now()
	app := newSweepTestApp(t, []store.Node{
		{ID: "a", IP: "198.51.100.1", ProbeStatus: "available", ProbedAt: now.Unix()},
		{ID: "b", IP: "198.51.100.2", ProbeStatus: "available", ProbedAt: now.Unix()},
		{ID: "stale", IP: "198.51.100.3", ProbeStatus: "available", ProbedAt: now.Add(-time.Hour).Unix()},
		{ID: "pending", IP: "198.51.100.4"},
	})
	got := app.pickSweepNodes(now)
	if len(got) != 1 || got[0] != "stale" {
		t.Fatalf("picked %v, want only stale", got)
	}
}
