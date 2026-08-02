//go:build !windows

package vpn

func ensureTAPAdapter(_ string) error {
	return nil
}

func openVPNDeviceArguments(device string, _ float64, _ string) []string {
	return []string{"--dev", device, "--dev-type", "tun"}
}

func openVPNDriverCandidates(_ float64) []string {
	return []string{""}
}

func shouldRetryOpenVPNDriver(_ error) bool {
	return false
}

func openVPNRouteArguments(routeNopull bool) []string {
	if routeNopull {
		return []string{"--route-nopull"}
	}
	return []string{"--pull-filter", "ignore", "dhcp-option"}
}
