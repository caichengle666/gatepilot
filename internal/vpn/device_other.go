//go:build !windows

package vpn

func openVPNDeviceArguments(device string, _ float64) []string {
	return []string{"--dev", device, "--dev-type", "tun"}
}

func openVPNRouteArguments(routeNopull bool) []string {
	if routeNopull {
		return []string{"--route-nopull"}
	}
	return []string{"--pull-filter", "ignore", "dhcp-option"}
}
