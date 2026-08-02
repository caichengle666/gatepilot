//go:build windows

package vpn

import "errors"

func openVPNDeviceArguments(_ string, version float64, driver string) []string {
	arguments := []string{"--dev", "tun"}
	if version >= 2.6 && driver != "" {
		arguments = append(arguments, "--windows-driver", driver)
	}
	return arguments
}

func openVPNDriverCandidates(version float64) []string {
	if version < 2.6 {
		return []string{""}
	}
	return []string{"wintun", "tap-windows6", "ovpn-dco"}
}

func shouldRetryOpenVPNDriver(err error) bool {
	var failure *openVPNFailure
	return errors.As(err, &failure) && (failure.code == "ERR_VPN_DRIVER" || failure.code == "ERR_VPN_PERMISSION")
}

func openVPNRouteArguments(routeNopull bool) []string {
	if routeNopull {
		return []string{"--pull-filter", "ignore", "redirect-gateway", "--pull-filter", "ignore", "route-gateway", "--route-nopull"}
	}
	return []string{"--pull-filter", "ignore", "dhcp-option"}
}
