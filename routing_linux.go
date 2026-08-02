//go:build linux

package main

import (
	"log"
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

func cleanupPolicyRouting() {
	_ = exec.Command("ip", "rule", "del", "table", "100").Run()
	_ = exec.Command("ip", "route", "flush", "table", "100").Run()
}
