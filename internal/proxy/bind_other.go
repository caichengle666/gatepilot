//go:build !linux && !windows

package proxy

import (
	"net"
	"time"
)

// DialVPN 通过 VPN 隧道拨号（其他平台直接连接）。
func DialVPN(address string, _ bool) (net.Conn, error) {
	return net.DialTimeout("tcp", address, 20*time.Second)
}
