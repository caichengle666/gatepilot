//go:build !windows

package store

func platformOpenVPNStatus(_ string) (bool, string) {
	return true, ""
}
