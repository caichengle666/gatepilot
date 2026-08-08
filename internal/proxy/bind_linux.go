//go:build linux

package proxy

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

// DialVPN 通过 VPN 隧道拨号（Linux 平台绑定到 tun0）。
func DialVPN(address string, requireTun bool) (net.Conn, error) {
	return DialVPNOnDevice(address, requireTun, "tun0")
}

// DialVPNOnDevice 通过指定的 Linux VPN 网卡拨号。
func DialVPNOnDevice(address string, requireTun bool, device string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}
	if requireTun {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) == nil {
			host, err = resolveVPNHost(host, device)
			if err != nil {
				return nil, err
			}
			address = net.JoinHostPort(host, port)
		}
		dialer.Control = bindToDevice(device)
	}
	return dialer.DialContext(context.Background(), "tcp", address)
}

func resolveVPNHost(host, device string) (string, error) {
	var lastError error
	for _, dnsServer := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: 5 * time.Second, Control: bindToDevice(device)}
				return dialer.DialContext(ctx, "udp", dnsServer)
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		addresses, err := resolver.LookupIPAddr(ctx, host)
		cancel()
		if err != nil {
			lastError = err
			continue
		}
		for _, address := range addresses {
			if address.IP.To4() != nil {
				return address.IP.String(), nil
			}
		}
		if len(addresses) > 0 {
			return addresses[0].IP.String(), nil
		}
		lastError = fmt.Errorf("DNS 未返回地址")
	}
	return "", fmt.Errorf("通过 VPN 解析 %s 失败: %w", host, lastError)
}

func bindToDevice(device string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, connection syscall.RawConn) error {
		var optionError error
		if err := connection.Control(func(fileDescriptor uintptr) {
			optionError = syscall.SetsockoptString(int(fileDescriptor), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		return optionError
	}
}
