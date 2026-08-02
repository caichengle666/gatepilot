//go:build windows

package store

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestDefaultOpenVPNCommandPrefersPortableDirectory(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "gatepilot.exe")
	if err := os.WriteFile(executable, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	openvpnDir := filepath.Join(root, "openvpn")
	if err := os.MkdirAll(openvpnDir, 0o755); err != nil {
		t.Fatal(err)
	}
	openvpnPath := filepath.Join(openvpnDir, "openvpn.exe")
	if err := os.WriteFile(openvpnPath, []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, want := defaultOpenVPNCommand(executable, nil), strconv.Quote(openvpnPath); got != want {
		t.Fatalf("defaultOpenVPNCommand = %q, want %q", got, want)
	}
}
