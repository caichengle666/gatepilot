//go:build windows

package vpn

import (
	"errors"
	"fmt"
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

func openVPNControlArguments(_ string) []string { return nil }

func setupPolicyRouting(_ string) {
	for attempt := 0; attempt < 15; attempt++ {
		if detectWindowsVPNAdapter() {
			return
		}
		time.Sleep(time.Second)
	}
}

func setupDevicePolicyRouting(_ string, _ int) {}

func setupEndpointMainRoute(_ string, _ int) bool { return false }

func cleanupEndpointMainRoute(_ string, _ int) {}

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
		looksLikeVPN := looksLikeWindowsVPNInterface(iface.Name)
		if routeInterfaceIndex == iface.Index && (changed || looksLikeVPN && isVPNGateIPv4(routeIP)) {
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

func waitForDeviceReady(_ string, _ time.Duration) error {
	return errors.New("附加 VPN 隧道仅支持 Linux")
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
			if ipv4 := firstInterfaceIPv4(iface); ipv4 != nil && (looksLikeWindowsVPNInterface(iface.Name) && isVPNGateIPv4(ipv4) || before[iface.Index] != iface.Name+"|"+ipv4.String()) {
				drain[iface.Index] = iface.Name
			}
		}
	}
	for interfaceIndex, interfaceName := range drain {
		drainWindowsVPNRoutes(interfaceIndex, interfaceName)
	}
}

func cleanupDevicePolicyRouting(_ string, _ int) {}

func cleanupStaleVPNState(openVPNCommand string) {
	_ = stopOpenVPNService(5 * time.Second)
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
	escaped := strings.ReplaceAll(openVPNExecutable, "'", "''")
	script := fmt.Sprintf(`$target = [IO.Path]::GetFullPath('%s'); Get-CimInstance Win32_Process -Filter "Name='openvpn.exe'" | Where-Object { $_.ExecutablePath -and [IO.Path]::GetFullPath($_.ExecutablePath) -eq $target -and -not (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`, escaped)
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, runErr := command.CombinedOutput(); runErr != nil {
		log.Printf("Unable to drain orphaned bundled OpenVPN processes: %v (%s)", runErr, strings.TrimSpace(string(output)))
	}
	time.Sleep(250 * time.Millisecond)
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if ipv4 := firstInterfaceIPv4(iface); looksLikeWindowsVPNInterface(iface.Name) && isVPNGateIPv4(ipv4) {
			drainWindowsVPNRoutes(iface.Index, iface.Name)
		}
	}
}

func isBundledOpenVPNExecutable(applicationExecutable, openVPNExecutable string) bool {
	expected := filepath.Join(filepath.Dir(applicationExecutable), "openvpn", "openvpn.exe")
	expectedPath, err := filepath.Abs(expected)
	if err != nil {
		return false
	}
	openVPNPath, err := filepath.Abs(openVPNExecutable)
	if err != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(expectedPath), filepath.Clean(openVPNPath))
}

func isVPNGateIPv4(ip net.IP) bool {
	ipv4 := ip.To4()
	return ipv4 != nil && ipv4[0] == 10
}

func looksLikeWindowsVPNInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"openvpn", "wintun", "tap", "tun"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
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
