package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/caichengle666/gatepilot/internal/proxy"
	"github.com/caichengle666/gatepilot/internal/store"
	"github.com/caichengle666/gatepilot/internal/vpn"
	"github.com/caichengle666/gatepilot/internal/web"
)

func main() {
	ensureAdminElevation()
	releaseInstance, err := acquireInstanceLock()
	if err != nil {
		log.Fatalf("GatePilot 启动失败: %v", err)
	}
	defer releaseInstance()
	config := store.LoadAppConfig()
	_, credentialsError := os.Stat(filepath.Join(config.DataDir, "ui_auth.json"))
	firstStart := os.IsNotExist(credentialsError)
	application, err := store.New(config)
	if err != nil {
		log.Fatalf("初始化数据目录失败: %v", err)
	}
	if err := ensureStartupPortsAvailable(application.Config); err != nil {
		log.Fatalf("GatePilot 启动失败: %v", err)
	}
	vpnCtrl := vpn.NewController(application)
	webApp := web.NewApplication(application, vpnCtrl)
	ui, _, _ := application.Snapshot()
	if err := store.ValidateProxyAuth(application.Config.ProxyHost, ui); err != nil {
		log.Fatalf("GatePilot 启动失败: %v", err)
	}
	proxyServer := proxy.NewServer(application.Config, ui)
	webApp.Proxy = proxyServer
	proxyServer.Failover = proxy.NewFailoverTracker(5, 30*time.Second, func(failures int) {
		log.Printf("代理连续 %d 次出站失败，触发自动切换节点", failures)
		webApp.TriggerAutoSwitch(failures)
	})
	proxy.EnsureGeoFiles()
	initSplitRouting(application, ui)
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
	log.Printf("管理地址: http://127.0.0.1:%d/%s/", ui.Port, ui.SecretPath)
	if firstStart {
		log.Printf("初始账号: %s  密码: %s", ui.Username, ui.Password)
	}
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

func initSplitRouting(application *store.Store, ui store.UIConfig) {
	if !ui.SplitRouting {
		return
	}
	rules := convertSplitRules(ui.SplitRules)
	defaultAction := proxy.RouteVPN
	if ui.SplitDefault == "direct" {
		defaultAction = proxy.RouteDirect
	}
	proxy.InitRouting(rules, defaultAction)
	log.Printf("分流规则已加载: %d 条规则, 默认 %s", len(rules), ui.SplitDefault)
}

func convertSplitRules(rules []store.SplitRule) []proxy.RouteRule {
	result := make([]proxy.RouteRule, 0, len(rules))
	for _, rule := range rules {
		var kind proxy.RuleKind
		switch rule.Kind {
		case "domain":
			kind = proxy.RuleDomain
		case "keyword":
			kind = proxy.RuleKeyword
		case "cidr":
			kind = proxy.RuleCIDR
		case "geosite":
			kind = proxy.RuleGeoSite
		case "geoip":
			kind = proxy.RuleGeoIP
		default:
			continue
		}
		action := proxy.RouteVPN
		if rule.Action == "direct" {
			action = proxy.RouteDirect
		}
		result = append(result, proxy.RouteRule{Kind: kind, Value: rule.Value, Action: action})
	}
	return result
}
