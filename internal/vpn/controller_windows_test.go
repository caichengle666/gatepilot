//go:build windows

package vpn

import (
	"reflect"
	"testing"
)

func TestOpenVPNDeviceArgumentsWindows(t *testing.T) {
	tests := []struct {
		version float64
		want    []string
	}{
		{version: 2.4, want: []string{"--dev", "tun"}},
		{version: 2.6, want: []string{"--dev", "tun", "--windows-driver", "wintun"}},
		{version: 2.7, want: []string{"--dev", "tun", "--windows-driver", "wintun"}},
	}
	for _, test := range tests {
		if got := openVPNDeviceArguments("tun0", test.version); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("version %.1f arguments = %v, want %v", test.version, got, test.want)
		}
	}
}

func TestWindowsNodeTestsAreSerial(t *testing.T) {
	if got := NodeTestWorkerCount(5); got != 1 {
		t.Fatalf("worker count = %d, want 1", got)
	}
}
