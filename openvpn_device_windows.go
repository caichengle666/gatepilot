//go:build windows

package main

func openVPNDeviceArguments(_ string, _ float64) []string {
	return []string{"--dev", "tun"}
}
