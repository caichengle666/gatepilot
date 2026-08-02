package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	config := loadAppConfig()
	application, err := newStore(config)
	if err != nil {
		log.Fatalf("初始化数据目录失败: %v", err)
	}
	vpn := newVPNController(application)
	web := newWebApplication(application, vpn)
	proxy := newProxyServer(application.config)
	web.proxy = proxy
	ui, _, _ := application.snapshot()
	log.Printf("管理地址: http://127.0.0.1:%d/%s/", ui.Port, ui.SecretPath)
	log.Printf("初始账号: %s  密码: %s", ui.Username, ui.Password)
	go func() {
		if err := proxy.serve(); err != nil {
			log.Printf("本地代理服务停止: %v", err)
		}
	}()
	if !application.config.DisableBackground {
		go backgroundMaintenance(web)
	}
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		<-signals
		vpn.stop("服务正在退出")
		os.Exit(0)
	}()
	if err := web.serve(); err != nil {
		log.Fatalf("Web 管理服务停止: %v", err)
	}
}
