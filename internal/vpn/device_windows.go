//go:build windows

package vpn

func openVPNDeviceArguments(_ string, version float64) []string {
	arguments := []string{"--dev", "tun"}
	if version >= 2.6 {
		arguments = append(arguments, "--windows-driver", "wintun")
	}
	return arguments
}

func openVPNRouteArguments(routeNopull bool) []string {
	if routeNopull {
		return []string{"--pull-filter", "ignore", "redirect-gateway", "--pull-filter", "ignore", "route-gateway", "--route-nopull"}
	}
	return []string{"--pull-filter", "ignore", "dhcp-option"}
}
