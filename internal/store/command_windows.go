//go:build windows

package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// DefaultOpenVPNCommand 返回 Windows 上 OpenVPN 可执行文件的默认路径。
func DefaultOpenVPNCommand() string {
	executable, _ := os.Executable()
	return defaultOpenVPNCommand(executable, []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")})
}

func defaultOpenVPNCommand(executable string, programFiles []string) string {
	paths := []string{}
	if executable != "" {
		root := filepath.Dir(executable)
		paths = append(paths,
			filepath.Join(root, "openvpn", "openvpn.exe"),
			filepath.Join(root, "openvpn.exe"),
		)
	}
	for _, root := range programFiles {
		if root == "" {
			continue
		}
		paths = append(paths, filepath.Join(root, "OpenVPN", "bin", "openvpn.exe"))
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return strconv.Quote(path)
		}
	}
	if path, err := exec.LookPath("openvpn.exe"); err == nil {
		return strconv.Quote(path)
	}
	return "openvpn.exe"
}
