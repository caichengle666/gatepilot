//go:build windows

package main

func openVPNDeviceArguments(_ string, version float64) []string {
	arguments := []string{"--dev", "tun"}
	if version >= 2.5 {
		arguments = append(arguments, "--windows-driver", "wintun")
	}
	return arguments
}
