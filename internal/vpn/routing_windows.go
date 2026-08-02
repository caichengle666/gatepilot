//go:build windows

package vpn

import (
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	routeInterfaceIndex, routeIP := activeRouteVPNInterface()
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
		changed := windowsVPNRoute.before[iface.Index] != signature
		name := strings.ToLower(iface.Name)
		looksLikeVPN := false
		for _, marker := range []string{"openvpn", "wintun", "tap", "tun"} {
			if strings.Contains(name, marker) {
				looksLikeVPN = true
				break
			}
		}
		if routeInterfaceIndex == iface.Index && (changed || isVPNGateIPv4(routeIP)) {
			score += 1000
			if routeIP != nil {
				ipv4 = append(net.IP(nil), routeIP...)
				signature = iface.Name + "|" + ipv4.String()
			}
		}
		if changed {
			score += 100
		}
		if looksLikeVPN {
			score += 50
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

// activeRouteVPNInterface 根据当前路由表探测默认出口网卡和本地 IPv4。
func activeRouteVPNInterface() (int, net.IP) {
	conn, err := net.DialTimeout("udp4", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		return 0, nil
	}
	defer conn.Close()
	localAddress, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddress.IP == nil {
		return 0, nil
	}
	localIP := localAddress.IP.To4()
	if localIP == nil {
		return 0, nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, localIP
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip.To4() != nil && ip.To4().Equal(localIP) {
				return iface.Index, localIP
			}
		}
	}
	return 0, localIP
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
	before := windowsVPNRoute.before
	selected := windowsVPNRoute.iface
	windowsVPNRoute.iface = net.Interface{}
	windowsVPNRoute.ipv4 = nil
	windowsVPNRoute.ready = false
	windowsVPNRoute.before = nil
	windowsVPNRoute.Unlock()
	drain := map[int]string{}
	if selected.Index > 0 {
		drain[selected.Index] = selected.Name
	}
	if before != nil {
		interfaces, _ := net.Interfaces()
		for _, iface := range interfaces {
			if ipv4 := firstInterfaceIPv4(iface); ipv4 != nil && (isVPNGateIPv4(ipv4) || before[iface.Index] != iface.Name+"|"+ipv4.String()) {
				drain[iface.Index] = iface.Name
			}
		}
	}
	for interfaceIndex, interfaceName := range drain {
		drainWindowsVPNRoutes(interfaceIndex, interfaceName)
	}
}

func cleanupStaleVPNState(openVPNCommand string) {
	parts, err := splitCommandLine(openVPNCommand)
	if err != nil || len(parts) == 0 {
		return
	}
	openVPNExecutable, err := exec.LookPath(parts[0])
	if err != nil {
		return
	}
	applicationExecutable, err := os.Executable()
	if err != nil || !isBundledOpenVPNExecutable(applicationExecutable, openVPNExecutable) {
		return
	}
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `Get-CimInstance Win32_Process -Filter "Name='openvpn.exe'" | Where-Object { -not (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, runErr := command.CombinedOutput(); runErr != nil {
		log.Printf("Unable to drain orphaned bundled OpenVPN processes: %v (%s)", runErr, strings.TrimSpace(string(output)))
	}
	time.Sleep(250 * time.Millisecond)
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if ipv4 := firstInterfaceIPv4(iface); isVPNGateIPv4(ipv4) {
			drainWindowsVPNRoutes(iface.Index, iface.Name)
		}
	}
}

func isBundledOpenVPNExecutable(applicationExecutable, openVPNExecutable string) bool {
	applicationDirectory, err := filepath.Abs(filepath.Dir(applicationExecutable))
	if err != nil {
		return false
	}
	openVPNPath, err := filepath.Abs(openVPNExecutable)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(applicationDirectory, openVPNPath)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	return len(parts) >= 2 && strings.EqualFold(parts[0], "openvpn")
}

func isVPNGateIPv4(ip net.IP) bool {
	ipv4 := ip.To4()
	return ipv4 != nil && ipv4[0] == 10 && ipv4[1] == 211 && ipv4[2] == 1
}

func windowsRouteDeleteArguments(interfaceIndex int) [][]string {
	if interfaceIndex <= 0 {
		return nil
	}
	index := strconv.Itoa(interfaceIndex)
	return [][]string{
		{"-4", "DELETE", "0.0.0.0", "MASK", "128.0.0.0", "IF", index},
		{"-4", "DELETE", "128.0.0.0", "MASK", "128.0.0.0", "IF", index},
	}
}

func drainWindowsVPNRoutes(interfaceIndex int, interfaceName string) {
	deleted := 0
	for _, arguments := range windowsRouteDeleteArguments(interfaceIndex) {
		for duplicate := 0; duplicate < 16; duplicate++ {
			command := exec.Command("route.exe", arguments...)
			command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			if err := command.Run(); err != nil {
				break
			}
			deleted++
		}
	}
	if deleted > 0 {
		log.Printf("Windows VPN route drain removed %d stale route entries from %s (index=%d)", deleted, interfaceName, interfaceIndex)
	}
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
