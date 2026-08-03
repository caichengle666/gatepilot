//go:build !windows

package vpn

import (
	"io"
	"os/exec"
)

func startOpenVPNProcess(command *exec.Cmd, _ string) (io.ReadCloser, managedOpenVPNProcess, <-chan error, error) {
	return startLocalOpenVPNProcess(command)
}

func RunWindowsOpenVPNService(_ []string) bool {
	return false
}

func PrepareWindowsOpenVPNService(_ string) (bool, error) {
	return false, nil
}
