//go:build linux

package vpn

import "testing"

func TestRedirectGatewayRoute(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		device string
		want   string
		ok     bool
	}{
		{name: "default split route", line: "0.0.0.0/1 via 10.8.0.1 dev tun0", device: "tun0", want: "0.0.0.0/1", ok: true},
		{name: "second split route", line: "128.0.0.0/1 via 10.8.0.1 dev tun0 metric 50", device: "tun0", want: "128.0.0.0/1", ok: true},
		{name: "other tunnel", line: "0.0.0.0/1 via 10.8.0.1 dev tun1", device: "tun0", ok: false},
		{name: "normal route", line: "default via 192.168.1.1 dev eth0", device: "tun0", ok: false},
		{name: "unrelated split route", line: "10.0.0.0/8 dev tun0", device: "tun0", ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := redirectGatewayRoute(test.line, test.device)
			if ok != test.ok || got != test.want {
				t.Fatalf("redirectGatewayRoute(%q, %q) = %q, %v; want %q, %v", test.line, test.device, got, ok, test.want, test.ok)
			}
		})
	}
}
