package vpn

import (
	"strings"
	"testing"
)

func TestSanitizeOpenVPNConfig(t *testing.T) {
	raw := "client\nscript-security 2\nup /tmp/evil\nplugin evil.so\nremote 127.0.0.1 1194\n<ca>\ncertificate\n</ca>\n"
	cleaned := sanitizeOpenVPNConfig(raw)
	for _, forbidden := range []string{"script-security", "up /tmp/evil", "plugin evil.so"} {
		if strings.Contains(cleaned, forbidden) {
			t.Fatalf("dangerous directive %q remains in config", forbidden)
		}
	}
	if !strings.Contains(cleaned, "remote 127.0.0.1 1194") || !strings.Contains(cleaned, "<ca>") {
		t.Fatalf("safe OpenVPN content was removed: %q", cleaned)
	}
}

func TestSplitOpenVPNCommand(t *testing.T) {
	parts, err := splitCommandLine(`"/opt/open vpn/openvpn" --config-extra 'value with spaces'`)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"/opt/open vpn/openvpn", "--config-extra", "value with spaces"}
	if len(parts) != len(expected) {
		t.Fatalf("unexpected command parts: %#v", parts)
	}
	for index := range expected {
		if parts[index] != expected[index] {
			t.Fatalf("unexpected command parts: %#v", parts)
		}
	}
}

func TestTunnelStatusSnapshotIsSortedAndIndependent(t *testing.T) {
	controller := &Controller{tunnels: map[string]*managedTunnel{
		"tun2": {TunnelStatus: TunnelStatus{Device: "tun2", NodeID: "US_test", ProxyPort: 7930, Table: 102}},
		"tun1": {TunnelStatus: TunnelStatus{Device: "tun1", NodeID: "JP_test", ProxyPort: 7929, Table: 101}},
	}}
	statuses := controller.Tunnels()
	if len(statuses) != 2 || statuses[0].Device != "tun1" || statuses[1].Device != "tun2" {
		t.Fatalf("unexpected tunnel order: %+v", statuses)
	}
	statuses[0].NodeID = "changed"
	if controller.tunnels["tun1"].NodeID != "JP_test" {
		t.Fatal("tunnel snapshot modified controller state")
	}
}
