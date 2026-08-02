package web

import "testing"

func TestIsLocalProxyEnvironmentFailure(t *testing.T) {
	tests := []struct {
		message string
		want    bool
	}{
		{message: `出口连接测试失败: Get "https://api.ip.sb/ip": Bad Gateway`, want: false},
		{message: "OpenVPN Windows adapter is not ready", want: true},
		{message: "i/o timeout", want: false},
		{message: "AUTH_FAILED", want: false},
	}
	for _, test := range tests {
		if got := isLocalProxyEnvironmentFailure(test.message); got != test.want {
			t.Fatalf("isLocalProxyEnvironmentFailure(%q) = %v, want %v", test.message, got, test.want)
		}
	}
}
