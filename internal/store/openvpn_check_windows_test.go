//go:build windows

package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsPortableOpenVPNStatusRequiresWintunFiles(t *testing.T) {
	root := t.TempDir()
	applicationExecutable := filepath.Join(root, "gatepilot.exe")
	openVPNDirectory := filepath.Join(root, "openvpn")
	if err := os.MkdirAll(openVPNDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"openvpn.exe", "libcrypto-3-x64.dll", "libssl-3-x64.dll", "libpkcs11-helper-1.dll", "vcruntime140.dll"} {
		if err := os.WriteFile(filepath.Join(openVPNDirectory, name), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ok, message := windowsPortableOpenVPNStatus(applicationExecutable, filepath.Join(openVPNDirectory, "openvpn.exe"))
	if ok || !strings.Contains(message, "wintun.dll") {
		t.Fatalf("status = %v, message = %q", ok, message)
	}
	if err := os.WriteFile(filepath.Join(openVPNDirectory, "wintun.dll"), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, message = windowsPortableOpenVPNStatus(applicationExecutable, filepath.Join(openVPNDirectory, "openvpn.exe"))
	if !ok || message != "" {
		t.Fatalf("status = %v, message = %q", ok, message)
	}
}

func TestWindowsPortableOpenVPNStatusAllowsExternalCore(t *testing.T) {
	ok, message := windowsPortableOpenVPNStatus(`C:\GatePilot\gatepilot.exe`, `C:\Program Files\OpenVPN\bin\openvpn.exe`)
	if !ok || message != "" {
		t.Fatalf("status = %v, message = %q", ok, message)
	}
}
