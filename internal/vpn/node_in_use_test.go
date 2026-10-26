package vpn

import (
	"context"
	"strings"
	"testing"

	"github.com/caichengle666/gatepilot/internal/store"
)

func newInUseTestController(t *testing.T) *Controller {
	t.Helper()
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	application.Nodes = []store.Node{
		{ID: "JP_main", IP: "60.34.127.120", RemotePort: 1437, Protocol: "udp", ProbeStatus: "available"},
		{ID: "JP_same_ip", IP: "60.34.127.120", RemotePort: 443, Protocol: "tcp", ProbeStatus: "available"},
		{ID: "TH_tunnel", IP: "27.130.34.32", ProbeStatus: "available"},
		{ID: "US_free", IP: "203.0.113.9", ProbeStatus: "available"},
	}
	return &Controller{application: application, tunnels: map[string]*managedTunnel{
		"tun2": {TunnelStatus: TunnelStatus{Device: "tun2", NodeID: "TH_tunnel", NodeIP: "27.130.34.32", ProxyPort: 7930}},
	}, nodeID: "JP_main"}
}

func TestNodeInUseDetectsMainAndTunnelByIDAndIP(t *testing.T) {
	controller := newInUseTestController(t)
	cases := []struct {
		id, exclude, owner string
		inUse              bool
	}{
		{"JP_main", "", "主连接", true},
		{"JP_same_ip", "", "主连接", true},
		{"JP_main", "tun0", "", false},
		{"TH_tunnel", "", "tun2", true},
		{"TH_tunnel", "tun2", "", false},
		{"TH_tunnel", "tun0", "tun2", true},
		{"US_free", "", "", false},
	}
	for _, item := range cases {
		owner, inUse := controller.NodeInUse(item.id, item.exclude)
		if inUse != item.inUse || owner != item.owner {
			t.Fatalf("NodeInUse(%s, %q) = %q,%v; want %q,%v", item.id, item.exclude, owner, inUse, item.owner, item.inUse)
		}
	}
	inUse := controller.InUseNodeIDs()
	if inUse["JP_main"] != "主连接" || inUse["JP_same_ip"] != "主连接" || inUse["TH_tunnel"] != "tun2" || inUse["US_free"] != "" {
		t.Fatalf("unexpected in-use map: %#v", inUse)
	}
}

func TestPendingMainNodeCountsAsInUse(t *testing.T) {
	controller := newInUseTestController(t)
	controller.nodeID = ""
	controller.pendingNodeID = "US_free"
	if owner, inUse := controller.NodeInUse("US_free", "tun1"); !inUse || owner != "主连接" {
		t.Fatalf("pending main node not treated as in use: %q %v", owner, inUse)
	}
}

func TestConnectRejectsNodeUsedByTunnel(t *testing.T) {
	controller := newInUseTestController(t)
	controller.nodeID = ""
	_, err := controller.ConnectContext(context.Background(), "TH_tunnel")
	if err == nil || !strings.Contains(err.Error(), "tun2") {
		t.Fatalf("expected main connect to be rejected, got %v", err)
	}
}
