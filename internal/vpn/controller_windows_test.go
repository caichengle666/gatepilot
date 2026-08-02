//go:build windows

package vpn

import (
	"net"
	"reflect"
	"testing"
)

func TestOpenVPNDeviceArgumentsWindows(t *testing.T) {
	tests := []struct {
		version float64
		driver  string
		want    []string
	}{
		{version: 2.4, driver: "", want: []string{"--dev", "tun"}},
		{version: 2.6, driver: "wintun", want: []string{"--dev", "tun", "--windows-driver", "wintun"}},
		{version: 2.7, driver: "tap-windows6", want: []string{"--dev", "tun", "--windows-driver", "tap-windows6"}},
	}
	for _, test := range tests {
		if got := openVPNDeviceArguments("tun0", test.version, test.driver); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("version %.1f arguments = %v, want %v", test.version, got, test.want)
		}
	}
}

func TestOpenVPNDriverCandidatesWindows(t *testing.T) {
	want := []string{"wintun", "tap-windows6", "ovpn-dco"}
	if got := openVPNDriverCandidates(2.6); !reflect.DeepEqual(got, want) {
		t.Fatalf("driver candidates = %v, want %v", got, want)
	}
	if !shouldRetryOpenVPNDriver(&openVPNFailure{code: "ERR_VPN_DRIVER"}) {
		t.Fatal("driver failures should trigger fallback")
	}
	if !shouldRetryOpenVPNDriver(&openVPNFailure{code: "ERR_VPN_PERMISSION"}) {
		t.Fatal("Wintun permission failures should trigger TAP fallback")
	}
	if shouldRetryOpenVPNDriver(&openVPNFailure{code: "ERR_VPN_TLS"}) {
		t.Fatal("network failures must not trigger driver fallback")
	}
}

func TestWindowsNodeTestsAreSerial(t *testing.T) {
	if got := NodeTestWorkerCount(5); got != 1 {
		t.Fatalf("worker count = %d, want 1", got)
	}
}

func TestWindowsRouteDeleteArgumentsAreScopedToInterface(t *testing.T) {
	want := [][]string{
		{"-4", "DELETE", "0.0.0.0", "MASK", "128.0.0.0", "IF", "5"},
		{"-4", "DELETE", "128.0.0.0", "MASK", "128.0.0.0", "IF", "5"},
	}
	if got := windowsRouteDeleteArguments(5); !reflect.DeepEqual(got, want) {
		t.Fatalf("route delete arguments = %v, want %v", got, want)
	}
	if got := windowsRouteDeleteArguments(0); got != nil {
		t.Fatalf("invalid interface should not produce delete arguments: %v", got)
	}
}

func TestBundledOpenVPNExecutableDetection(t *testing.T) {
	if !isBundledOpenVPNExecutable(`C:\GatePilot\gatepilot.exe`, `C:\GatePilot\openvpn\openvpn.exe`) {
		t.Fatal("portable OpenVPN core should be detected")
	}
	if isBundledOpenVPNExecutable(`C:\GatePilot\gatepilot.exe`, `C:\Program Files\OpenVPN\bin\openvpn.exe`) {
		t.Fatal("system OpenVPN installation must not be treated as bundled")
	}
}

func TestVPNGateIPv4Detection(t *testing.T) {
	if !isVPNGateIPv4(net.ParseIP("10.211.1.25")) {
		t.Fatal("VPNGate tunnel address should be detected")
	}
	if !isVPNGateIPv4(net.ParseIP("10.238.223.11")) {
		t.Fatal("VPNGate tunnel address outside 10.211.1.0/24 should be detected")
	}
	if isVPNGateIPv4(net.ParseIP("192.168.2.11")) {
		t.Fatal("physical LAN address must not be detected as VPNGate")
	}
}
