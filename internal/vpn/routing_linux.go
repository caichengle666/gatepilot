//go:build linux

package vpn

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"
)

func setupPolicyRouting(device string) {
	setupDevicePolicyRouting(device, 100)
	cleanupRedirectGatewayRoutes(device)
}

func setupDevicePolicyRouting(device string, table int) {
	cleanupDevicePolicyRouting(device, table)
	tableName := fmt.Sprintf("%d", table)
	for attempt := 1; attempt <= 3; attempt++ {
		if err := exec.Command("ip", "route", "add", "default", "dev", device, "table", tableName).Run(); err != nil {
			log.Printf("策略路由表配置第 %d 次失败: %v", attempt, err)
			time.Sleep(time.Second)
			continue
		}
		if err := exec.Command("ip", "rule", "add", "pref", fmt.Sprint(1000+table-100), "oif", device, "table", tableName).Run(); err != nil {
			log.Printf("策略路由规则配置第 %d 次失败: %v", attempt, err)
			cleanupDevicePolicyRouting(device, table)
			time.Sleep(time.Second)
			continue
		}
		for _, target := range []string{"all", "default", device} {
			_ = exec.Command("sysctl", "-w", "net.ipv4.conf."+target+".rp_filter=2").Run()
		}
		return
	}
	log.Printf("[ERR_ROUTE_TABLE_ADD_FAILED] 无法为 %s 配置策略路由表 %d", device, table)
}

func setupEndpointMainRoute(host string, priority int) bool {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return false
	}
	return exec.Command("ip", "rule", "add", "pref", fmt.Sprint(priority), "to", ip.To4().String(), "lookup", "main").Run() == nil
}

func cleanupEndpointMainRoute(host string, priority int) {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return
	}
	_ = exec.Command("ip", "rule", "del", "pref", fmt.Sprint(priority), "to", ip.To4().String(), "lookup", "main").Run()
}

func preparePolicyRouting() {}

func openVPNControlArguments(device string) []string {
	if !strings.HasPrefix(device, "tun") || device == "tun0" {
		return nil
	}
	output, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(output))
	for index, field := range fields {
		if field == "dev" && index+1 < len(fields) {
			return []string{"--bind-dev", fields[index+1]}
		}
	}
	return nil
}

func waitForVPNReady(timeout time.Duration) error {
	return waitForDeviceReady("tun0", timeout)
}

func waitForDeviceReady(device string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if iface, err := net.InterfaceByName(device); err == nil && iface.Flags&net.FlagUp != 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("%s 未就绪，请确认以 root 运行并启用 /dev/net/tun", device)
}
func cleanupPolicyRouting() {
	cleanupDevicePolicyRouting("tun0", 100)
	cleanupRedirectGatewayRoutes("tun0")
}

func cleanupRedirectGatewayRoutes(device string) {
	if !strings.HasPrefix(device, "tun") {
		return
	}
	out, err := exec.Command("ip", "route", "show", "table", "main").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		destination, ok := redirectGatewayRoute(line, device)
		if !ok {
			continue
		}
		_ = exec.Command("ip", "route", "del", destination, "dev", device).Run()
	}
}

func redirectGatewayRoute(line, device string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || (fields[0] != "0.0.0.0/1" && fields[0] != "128.0.0.0/1") {
		return "", false
	}
	for index := 1; index+1 < len(fields); index++ {
		if fields[index] == "dev" && fields[index+1] == device {
			return fields[0], true
		}
	}
	return "", false
}

func cleanupDevicePolicyRouting(device string, table int) {
	tableName := fmt.Sprintf("%d", table)
	for {
		if err := exec.Command("ip", "rule", "del", "pref", fmt.Sprint(1000+table-100), "oif", device, "table", tableName).Run(); err != nil {
			break
		}
	}
	_ = exec.Command("ip", "route", "flush", "table", tableName).Run()
}
