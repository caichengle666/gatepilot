//go:build windows

package vpn

import "testing"

func TestValidateOpenVPNServiceArguments(t *testing.T) {
	arguments := []string{
		"--config", `C:\GatePilot\data\node.ovpn`,
		"--pull-filter", "ignore", "route-ipv6",
		"--auth-user-pass", `C:\GatePilot\data\auth.txt`,
		"--auth-nocache",
		"--dev", "tun",
		"--windows-driver", "wintun",
		"--dev-node", "OpenVPN",
		"--http-proxy", "127.0.0.1", "7890", `C:\GatePilot\data\proxy-auth.txt`,
		"--verb", "3",
	}
	if err := validateOpenVPNServiceArguments(arguments); err != nil {
		t.Fatalf("valid generated arguments rejected: %v", err)
	}
}

func TestValidateOpenVPNServiceArgumentsRejectsUnsafeOptions(t *testing.T) {
	arguments := []string{
		"--config", `C:\GatePilot\data\node.ovpn`,
		"--windows-driver", "wintun",
		"--plugin", `C:\untrusted.dll`,
	}
	if err := validateOpenVPNServiceArguments(arguments); err == nil {
		t.Fatal("service must reject options that can load arbitrary code")
	}
}

func TestValidateOpenVPNServiceArgumentsRequiresWintun(t *testing.T) {
	arguments := []string{"--config", `C:\GatePilot\data\node.ovpn`, "--windows-driver", "tap-windows6"}
	if err := validateOpenVPNServiceArguments(arguments); err == nil {
		t.Fatal("SYSTEM service is only intended for the Wintun primary path")
	}
}
