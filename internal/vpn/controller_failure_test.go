package vpn

import (
	"errors"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestSplitOpenVPNCommandWindowsPaths(t *testing.T) {
	parts, err := splitCommandLine(`D:\Tools\OpenVPN\bin\openvpn.exe --config-extra value`)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 3 || parts[0] != `D:\Tools\OpenVPN\bin\openvpn.exe` || parts[1] != "--config-extra" || parts[2] != "value" {
		t.Fatalf("unexpected command parts: %#v", parts)
	}
}

func TestSplitOpenVPNCommandTrailingBackslash(t *testing.T) {
	parts, err := splitCommandLine(`D:\Tools\`)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || parts[0] != `D:\Tools\` {
		t.Fatalf("unexpected command parts: %#v", parts)
	}
}

func TestOpenVPNFailureBlacklistClassification(t *testing.T) {
	if !shouldBlacklistOpenVPNFailure(&openVPNFailure{code: "ERR_VPN_AUTH"}) {
		t.Fatal("authentication failures should blacklist nodes")
	}
	if shouldBlacklistOpenVPNFailure(&openVPNFailure{code: "ERR_VPN_EXEC"}) {
		t.Fatal("missing executable failures must not blacklist nodes")
	}
	if shouldBlacklistOpenVPNFailure(errors.New("plain error")) {
		t.Fatal("untyped errors must not blacklist nodes")
	}
}

func TestOpenVPNErrorMissingExecutable(t *testing.T) {
	controller := &Controller{}
	err := controller.openVPNError(exec.ErrNotFound, nil)
	if !strings.Contains(err.Error(), "[ERR_VPN_EXEC]") {
		t.Fatalf("unexpected error: %v", err)
	}
	if shouldBlacklistOpenVPNFailure(err) {
		t.Fatalf("missing executable should not blacklist nodes: %v", err)
	}
}

func TestOpenVPNErrorPreservesDriverFailure(t *testing.T) {
	controller := &Controller{}
	original := &openVPNFailure{code: "ERR_VPN_PERMISSION", message: "service unavailable"}
	err := controller.openVPNError(original, nil)
	if err != original {
		t.Fatalf("typed OpenVPN failure was wrapped: %v", err)
	}
}

func TestOpenVPNErrorEnvironmentFailuresDoNotBlacklist(t *testing.T) {
	controller := &Controller{}
	for _, tail := range [][]string{
		{"ERROR:  Wintun requires SYSTEM privileges and therefore should be used with interactive service."},
		{"All tap-windows6 adapters on this system are currently in use or disabled."},
	} {
		err := controller.openVPNError(errors.New("exit status 1"), tail)
		if shouldBlacklistOpenVPNFailure(err) {
			t.Fatalf("environment failure should not blacklist nodes: %v", err)
		}
	}
	authErr := controller.openVPNError(errors.New("exit status 1"), []string{"AUTH: Received control message: AUTH_FAILED"})
	if !shouldBlacklistOpenVPNFailure(authErr) {
		t.Fatalf("authentication failure should blacklist nodes: %v", authErr)
	}
}

func TestOpenVPNRouteArguments(t *testing.T) {
	got := openVPNRouteArguments(true)
	if len(got) == 0 {
		t.Fatal("routeNopull arguments should not be empty")
	}
	joined := strings.Join(got, " ")
	expected := []string{"--pull-filter ignore redirect-gateway", "--route-nopull"}
	if runtime.GOOS != "windows" {
		expected = append([]string{"--pull-filter ignore dhcp-option"}, expected...)
	}
	for _, argument := range expected {
		if !strings.Contains(joined, argument) {
			t.Fatalf("routeNopull arguments missing %q: %#v", argument, got)
		}
	}
	if got := openVPNRouteArguments(false); len(got) == 0 {
		t.Fatal("normal route arguments should not be empty")
	}
}

func TestSocks5RequiresAuth(t *testing.T) {
	tests := []struct {
		name  string
		reply byte
		want  bool
	}{
		{name: "no auth", reply: 0x00, want: false},
		{name: "username password", reply: 0x02, want: true},
	}
	for _, test := range tests {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func(reply byte) {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			defer connection.Close()
			buffer := make([]byte, 4)
			if _, err := connection.Read(buffer); err != nil {
				return
			}
			_, _ = connection.Write([]byte{0x05, reply})
		}(test.reply)
		host, port, err := net.SplitHostPort(listener.Addr().String())
		if err != nil {
			listener.Close()
			t.Fatal(err)
		}
		got := socks5RequiresAuth(host, port)
		listener.Close()
		if got != test.want {
			t.Fatalf("%s: socks5RequiresAuth = %v, want %v", test.name, got, test.want)
		}
	}
}
