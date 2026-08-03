//go:build windows

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func platformOpenVPNStatus(openVPNExecutable string) (bool, string) {
	applicationExecutable, err := os.Executable()
	if err != nil {
		return false, "无法确定 GatePilot 程序目录。"
	}
	return windowsPortableOpenVPNStatus(applicationExecutable, openVPNExecutable)
}

func windowsPortableOpenVPNStatus(applicationExecutable, openVPNExecutable string) (bool, string) {
	expected := filepath.Join(filepath.Dir(applicationExecutable), "openvpn", "openvpn.exe")
	openVPNPath, openVPNErr := filepath.Abs(openVPNExecutable)
	expectedPath, expectedErr := filepath.Abs(expected)
	if openVPNErr != nil || expectedErr != nil || !strings.EqualFold(filepath.Clean(openVPNPath), filepath.Clean(expectedPath)) {
		return true, ""
	}
	required := []string{
		"openvpn.exe",
		"libcrypto-3-x64.dll",
		"libssl-3-x64.dll",
		"libpkcs11-helper-1.dll",
		"vcruntime140.dll",
		"wintun.dll",
	}
	directory := filepath.Dir(expectedPath)
	missing := make([]string, 0)
	for _, name := range required {
		if info, err := os.Stat(filepath.Join(directory, name)); err != nil || info.IsDir() {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return false, fmt.Sprintf("Windows 便携核心不完整，缺少文件: %s。", strings.Join(missing, ", "))
	}
	return true, ""
}
