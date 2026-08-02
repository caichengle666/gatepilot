//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
)

func defaultOpenVPNCommand() string {
	for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if root == "" {
			continue
		}
		path := filepath.Join(root, "OpenVPN", "bin", "openvpn.exe")
		if _, err := os.Stat(path); err == nil {
			return strconv.Quote(path)
		}
	}
	return "openvpn.exe"
}
