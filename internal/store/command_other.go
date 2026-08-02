//go:build !windows

package store

// DefaultOpenVPNCommand 返回非 Windows 平台上 OpenVPN 命令。
func DefaultOpenVPNCommand() string {
	return "openvpn"
}
