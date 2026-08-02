//go:build windows

package vpn

import (
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

var windowsVPNRoute struct {
	sync.RWMutex
	before map[int]string
	iface  net.Interface
	ipv4   net.IP
	ready  bool
}

// ActiveVPNInterface 返回当前活动的 Windows VPN 网卡信息。
func ActiveVPNInterface() (net.Interface, net.IP, error) {
	windowsVPNRoute.RLock()
	defer windowsVPNRoute.RUnlock()
	if !windowsVPNRoute.ready {
		return net.Interface{}, nil, net.UnknownNetworkError("OpenVPN Windows adapter is not ready")
	}
	return windowsVPNRoute.iface, append(net.IP(nil), windowsVPNRoute.ipv4...), nil
}

func preparePolicyRouting() {
	windowsVPNRoute.Lock()
	windowsVPNRoute.before = windowsInterfaceSnapshot()
	windowsVPNRoute.Unlock()
}

func setupPolicyRouting(_ string) {
	for attempt := 0; attempt < 15; attempt++ {
		if detectWindowsVPNAdapter() {
			return
		}
		time.Sleep(time.Second)
	}
}

func detectWindowsVPNAdapter() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Unable to enumerate Windows VPN adapters: %v", err)
		return false
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
		return false
	}
	log.Printf("Windows VPN adapter selected: %s (index=%d, ip=%s)", windowsVPNRoute.iface.Name, windowsVPNRoute.iface.Index, windowsVPNRoute.ipv4)
	return true
}

func waitForVPNReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, _, err := ActiveVPNInterface(); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("OpenVPN 虚拟网卡未就绪，请确认以管理员/SYSTEM 权限运行并安装 Wintun/TAP/DCO 驱动")
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
