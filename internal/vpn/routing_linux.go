//go:build linux

package vpn

import (
	"errors"
	"log"
	"net"
	"os/exec"
	"time"
)

func setupPolicyRouting(device string) {
	cleanupPolicyRouting()
	for attempt := 1; attempt <= 3; attempt++ {
		if err := exec.Command("ip", "route", "add", "default", "dev", device, "table", "100").Run(); err != nil {
			log.Printf("策略路由表配置第 %d 次失败: %v", attempt, err)
			time.Sleep(time.Second)
			continue
		}
		if err := exec.Command("ip", "rule", "add", "oif", device, "table", "100").Run(); err != nil {
			log.Printf("策略路由规则配置第 %d 次失败: %v", attempt, err)
			cleanupPolicyRouting()
			time.Sleep(time.Second)
			continue
		}
		for _, target := range []string{"all", "default", device} {
			_ = exec.Command("sysctl", "-w", "net.ipv4.conf."+target+".rp_filter=2").Run()
		}
		return
	}
	log.Printf("[ERR_ROUTE_TABLE_ADD_FAILED] 无法为 %s 配置策略路由表 100", device)
}

func preparePolicyRouting() {}

func waitForVPNReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if iface, err := net.InterfaceByName("tun0"); err == nil && iface.Flags&net.FlagUp != 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("tun0 未就绪，请确认以 root 运行并启用 /dev/net/tun")
}
func cleanupPolicyRouting() {
	_ = exec.Command("ip", "rule", "del", "table", "100").Run()
	_ = exec.Command("ip", "route", "flush", "table", "100").Run()
}
