//go:build !windows

package main

func defaultOpenVPNCommand() string {
	return "openvpn"
}
