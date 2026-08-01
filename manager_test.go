package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

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

func TestFavoriteRoutingWithoutFallback(t *testing.T) {
	application := &store{
		ui:    uiConfig{RoutingMode: "favorites", FavoriteNodeIDs: []string{"favorite"}},
		nodes: []node{{ID: "other", Score: 100}, {ID: "favorite", Score: 1}},
	}
	candidates := application.candidates()
	if len(candidates) != 1 || candidates[0].ID != "favorite" {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
}
