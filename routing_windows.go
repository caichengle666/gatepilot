//go:build windows

package main

import (
	"log"
	"net"
	"strings"
	"sync"
)

var windowsVPNRoute struct {
	sync.RWMutex
	before map[int]string
	iface  net.Interface
	ipv4   net.IP
	ready  bool
}

func preparePolicyRouting() {
	windowsVPNRoute.Lock()
	windowsVPNRoute.before = windowsInterfaceSnapshot()
	windowsVPNRoute.Unlock()
}

func setupPolicyRouting(_ string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Unable to enumerate Windows VPN adapters: %v", err)
		return
	}
	windowsVPNRoute.Lock()
	defer windowsVPNRoute.Unlock()
	bestScore := 0
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ipv4 := firstInterfaceIPv4(iface)
		if ipv4 == nil {
			continue
		}
		signature := iface.Name + "|" + ipv4.String()
		score := 0
		if windowsVPNRoute.before[iface.Index] != signature {
			score += 100
		}
		name := strings.ToLower(iface.Name)
		for _, marker := range []string{"openvpn", "wintun", "tap", "tun"} {
			if strings.Contains(name, marker) {
				score += 50
				break
			}
		}
		if score > bestScore {
			bestScore = score
			windowsVPNRoute.iface = iface
			windowsVPNRoute.ipv4 = append(net.IP(nil), ipv4...)
			windowsVPNRoute.ready = true
		}
	}
	if !windowsVPNRoute.ready {
		log.Printf("OpenVPN connected, but its Windows adapter could not be identified")
		return
	}
	log.Printf("Windows VPN adapter selected: %s (index=%d, ip=%s)", windowsVPNRoute.iface.Name, windowsVPNRoute.iface.Index, windowsVPNRoute.ipv4)
}

func cleanupPolicyRouting() {
	windowsVPNRoute.Lock()
	windowsVPNRoute.iface = net.Interface{}
	windowsVPNRoute.ipv4 = nil
	windowsVPNRoute.ready = false
	windowsVPNRoute.Unlock()
}

func windowsInterfaceSnapshot() map[int]string {
	result := map[int]string{}
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if ipv4 := firstInterfaceIPv4(iface); ipv4 != nil {
			result[iface.Index] = iface.Name + "|" + ipv4.String()
		}
	}
	return result
}

func firstInterfaceIPv4(iface net.Interface) net.IP {
	addresses, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil {
			return ip.To4()
		}
	}
	return nil
}
