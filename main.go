package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/caichengle666/gatepilot/internal/proxy"
	"github.com/caichengle666/gatepilot/internal/store"
	"github.com/caichengle666/gatepilot/internal/vpn"
	"github.com/caichengle666/gatepilot/internal/web"
)

func main() {
	ensureAdminElevation()
	config := store.LoadAppConfig()
	application, err := store.New(config)
	if err != nil {
		log.Fatalf("初始化数据目录失败: %v", err)
	}
	vpnCtrl := vpn.NewController(application)
	webApp := web.NewApplication(application, vpnCtrl)
	proxyServer := proxy.NewServer(application.Config)
	webApp.Proxy = proxyServer
	if ok, message := store.OpenVPNStatus(application.Config.OpenVPNCommand); ok {
		_ = application.UpdateState(func(state *store.RuntimeState) {
			state.OpenVPNOK = true
			state.OpenVPNMessage = ""
		})
		log.Printf("OpenVPN 核心检测正常: %s", application.Config.OpenVPNCommand)
	} else {
		_ = application.UpdateState(func(state *store.RuntimeState) {
			state.OpenVPNOK = false
			state.OpenVPNMessage = message
		})
		log.Printf("OpenVPN 核心不可用: %s", message)
	}
	ui, _, _ := application.Snapshot()
	log.Printf("管理地址: http://127.0.0.1:%d/%s/", ui.Port, ui.SecretPath)
	log.Printf("初始账号: %s  密码: %s", ui.Username, ui.Password)
	go func() {
		if err := proxyServer.Serve(); err != nil {
			log.Printf("本地代理服务停止: %v", err)
		}
	}()
	if !application.Config.DisableBackground {
		go web.BackgroundMaintenance(webApp)
	}
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		<-signals
		vpnCtrl.Stop("服务正在退出")
		os.Exit(0)
	}()
	if err := webApp.Serve(); err != nil {
		log.Fatalf("Web 管理服务停止: %v", err)
	}
}
