package store

import (
	"errors"
	"testing"
)

func TestDiagnoseOpenVPNFailureEnvironmentErrors(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		cause    error
		wantCode string
	}{
		{name: "missing executable", cause: errors.New(`exec: "openvpn.exe": executable file not found in %PATH%`), wantCode: "ERR_VPN_EXEC"},
		{name: "wintun system privileges", output: "ERROR:  Wintun requires SYSTEM privileges and therefore should be used with interactive service.", wantCode: "ERR_VPN_PERMISSION"},
		{name: "tap adapters unavailable", output: "All tap-windows6 adapters on this system are currently in use or disabled.", wantCode: "ERR_VPN_DRIVER"},
		{name: "authentication failure", output: "AUTH: Received control message: AUTH_FAILED", wantCode: "ERR_VPN_AUTH"},
		{name: "tcp connection timeout", output: "TCP: connect to [AF_INET]174.74.228.39:1991 failed: Connection timed out", wantCode: "ERR_VPN_TIMEOUT"},
	}
	for _, test := range tests {
		code, message := DiagnoseOpenVPNFailure(test.output, test.cause)
		if code != test.wantCode {
			t.Fatalf("%s: code = %s, want %s (%s)", test.name, code, test.wantCode, message)
		}
	}
}
