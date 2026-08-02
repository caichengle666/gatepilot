//go:build !windows

package main

func openVPNDeviceArguments(device string, _ float64) []string {
	return []string{"--dev", device, "--dev-type", "tun"}
}
