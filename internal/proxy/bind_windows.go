//go:build windows

package proxy

import (
	"context"
	"fmt"
	"math/bits"
	"net"
	"syscall"
	"time"

	"github.com/caichengle666/gatepilot/internal/vpn"
)

const windowsIPUnicastIF = 31

// DialVPN 通过 VPN 隧道拨号（Windows 平台绑定到 VPN 网卡）。
func DialVPN(address string, requireTun bool) (net.Conn, error) {
	if !requireTun {
		return net.DialTimeout("tcp", address, 20*time.Second)
	}
	iface, localIP, err := vpn.ActiveVPNInterface()
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		host, err = resolveWindowsVPNHost(host, iface, localIP)
		if err != nil {
			return nil, err
		}
		address = net.JoinHostPort(host, port)
	}
	dialer := net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: &net.TCPAddr{IP: localIP},
		Control:   windowsInterfaceControl(iface.Index),
	}
	return dialer.DialContext(context.Background(), "tcp4", address)
}

// DialVPNOnDevice 在 Windows 上只支持当前活动的 OpenVPN 网卡。
func DialVPNOnDevice(address string, requireTun bool, _ string) (net.Conn, error) {
	return DialVPN(address, requireTun)
}

func resolveWindowsVPNHost(host string, iface net.Interface, localIP net.IP) (string, error) {
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout:   5 * time.Second,
				LocalAddr: &net.UDPAddr{IP: localIP},
				Control:   windowsInterfaceControl(iface.Index),
			}
			return dialer.DialContext(ctx, "udp4", "1.1.1.1:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve %s through OpenVPN failed: %w", host, err)
	}
	for _, address := range addresses {
		if ipv4 := address.IP.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("resolve %s through OpenVPN returned no IPv4 address", host)
}

func windowsInterfaceControl(index int) func(string, string, syscall.RawConn) error {
	return func(_, _ string, connection syscall.RawConn) error {
		var optionError error
		if err := connection.Control(func(handle uintptr) {
			value := int(bits.ReverseBytes32(uint32(index)))
			optionError = syscall.SetsockoptInt(syscall.Handle(handle), syscall.IPPROTO_IP, windowsIPUnicastIF, value)
		}); err != nil {
			return err
		}
		return optionError
	}
}
