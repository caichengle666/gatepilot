package store

import (
	"runtime"
	"strings"
	"testing"
)

func TestOpenVPNStatusMissingCommand(t *testing.T) {
	ok, message := OpenVPNStatus("definitely-missing-openvpn-binary")
	if ok {
		t.Fatal("expected missing OpenVPN command to be unavailable")
	}
	if !strings.Contains(message, "找不到 OpenVPN 核心程序") {
		t.Fatalf("unexpected message: %q", message)
	}
	switch runtime.GOOS {
	case "windows":
		if !strings.Contains(message, "Windows 便携版") {
			t.Fatalf("windows hint missing: %q", message)
		}
	case "darwin":
		if !strings.Contains(message, "brew install openvpn") {
			t.Fatalf("macos hint missing: %q", message)
		}
	default:
		if !strings.Contains(message, "apt install openvpn") {
			t.Fatalf("linux hint missing: %q", message)
		}
	}
}

func TestSplitOpenVPNCommandPreservesWindowsBackslashes(t *testing.T) {
	parts, err := splitOpenVPNCommand(`"D:\Tools\OpenVPN\bin\openvpn.exe" --version`)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 || parts[0] != `D:\Tools\OpenVPN\bin\openvpn.exe` || parts[1] != "--version" {
		t.Fatalf("unexpected command parts: %#v", parts)
	}
}
