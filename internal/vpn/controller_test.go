package vpn

import (
	"reflect"
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

func TestOpenVPNDeviceArgumentsWindows(t *testing.T) {
	tests := []struct {
		version float64
		want    []string
	}{
		{version: 2.4, want: []string{"--dev", "tun"}},
		{version: 2.6, want: []string{"--dev", "tun", "--windows-driver", "wintun"}},
		{version: 2.7, want: []string{"--dev", "tun", "--windows-driver", "wintun"}},
	}
	for _, test := range tests {
		if got := openVPNDeviceArguments("tun0", test.version); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("version %.1f arguments = %v, want %v", test.version, got, test.want)
		}
	}
}

func TestWindowsNodeTestsAreSerial(t *testing.T) {
	if got := NodeTestWorkerCount(5); got != 1 {
		t.Fatalf("worker count = %d, want 1", got)
	}
}
