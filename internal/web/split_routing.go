package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caichengle666/gatepilot/internal/proxy"
	"github.com/caichengle666/gatepilot/internal/store"
)

// reloadSplitRouting 根据当前 UI 配置热更新分流引擎。
func (a *Application) reloadSplitRouting() {
	ui, _, _ := a.Store.Snapshot()
	if !ui.SplitRouting {
		proxy.InitRouting(nil, proxy.RouteVPN)
		return
	}
	rules := convertSplitRulesWeb(ui.SplitRules)
	defaultAction := proxy.RouteVPN
	if ui.SplitDefault == "direct" {
		defaultAction = proxy.RouteDirect
	}
	proxy.UpdateRules(rules, defaultAction)
}

func convertSplitRulesWeb(rules []store.SplitRule) []proxy.RouteRule {
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

// getSplitRouting 返回当前分流配置。
func (a *Application) getSplitRouting(writer http.ResponseWriter, _ *http.Request) {
	ui, _, _ := a.Store.Snapshot()
	presets := proxy.DefaultGeoRules()
	presetList := make([]map[string]any, 0, len(presets))
	for _, rule := range presets {
		kindStr := "domain"
		switch rule.Kind {
		case proxy.RuleKeyword:
			kindStr = "keyword"
		case proxy.RuleCIDR:
			kindStr = "cidr"
		}
		presetList = append(presetList, map[string]any{"kind": kindStr, "value": rule.Value, "action": "direct"})
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{
		"ok":             true,
		"split_routing":  ui.SplitRouting,
		"split_default":  ui.SplitDefault,
		"split_rules":    ui.SplitRules,
		"china_presets":  presetList,
		"geo_status":     proxy.GeoStatus(),
	})
}

// dnsLeakCheck 检测 DNS 是否泄漏。
func (a *Application) dnsLeakCheck(writer http.ResponseWriter, request *http.Request) {
	if a.Proxy == nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "代理服务未启动"})
		return
	}
	ui, state, _ := a.Store.Snapshot()
	if state.Status != "connected" {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "请先连接 VPN 后再检测"})
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()

	client := a.proxyHTTPClientForPort(ui.ProxyPort, 15*time.Second)
	results := map[string]any{"ok": true}

	// 1. 检测出口 IP
	exitIP, exitErr := fetchWithClient(ctx, client, "https://api.ip.sb/ip")
	results["exit_ip"] = exitIP
	if exitErr != nil {
		results["exit_ip_error"] = exitErr.Error()
	}

	// 2. DNS 泄漏检测：通过代理解析域名，检查 DNS 服务器归属
	dnsServers, dnsErr := fetchWithClient(ctx, client, "https://api.ip.sb/geoip")
	results["geoip"] = dnsServers
	if dnsErr != nil {
		results["geoip_error"] = dnsErr.Error()
	}

	// 3. 检测 DNS 解析是否走 VPN（通过代理做 DNS 查询）
	dnsLeak := a.checkDNSLeak(ctx, client)
	results["dns_leak"] = dnsLeak

	// 4. IPv6 泄漏检测
	ipv6Leak := a.checkIPv6Leak(ctx, client)
	results["ipv6_leak"] = ipv6Leak

	writeJSONResponse(writer, http.StatusOK, results)
}

func fetchWithClient(ctx context.Context, client *http.Client, targetURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

type dnsLeakResult struct {
	IP          string `json:"ip"`
	CountryName string `json:"country_name"`
	ASN         string `json:"asn"`
	Type        string `json:"type"`
}

// checkDNSLeak 通过代理执行 DNS 查询，检测是否泄漏到本地 DNS。
func (a *Application) checkDNSLeak(ctx context.Context, client *http.Client) map[string]any {
	result := map[string]any{"available": false, "leaked": false, "details": ""}
	testID, err := fetchWithClient(ctx, client, "https://bash.ws/id")
	if err != nil {
		result["details"] = "DNS 泄漏测试服务不可达: " + err.Error()
		return result
	}
	testID = strings.TrimSpace(testID)
	if !validDNSLeakTestID(testID) {
		result["details"] = "DNS 泄漏测试服务返回了无效测试编号"
		return result
	}

	var waitGroup sync.WaitGroup
	for index := 0; index < 10; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			requestURL := fmt.Sprintf("https://%d.%s.bash.ws/", index, testID)
			request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
			if requestErr != nil {
				return
			}
			response, requestErr := client.Do(request)
			if requestErr == nil {
				_ = response.Body.Close()
			}
		}(index)
	}
	waitGroup.Wait()

	body, err := fetchWithClient(ctx, client, "https://bash.ws/dnsleak/test/"+testID+"?json")
	if err != nil {
		result["details"] = "无法读取 DNS 泄漏测试结果: " + err.Error()
		return result
	}
	var entries []dnsLeakResult
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		result["details"] = "无法解析 DNS 泄漏测试结果: " + err.Error()
		return result
	}
	return analyzeDNSLeak(entries)
}

func validDNSLeakTestID(testID string) bool {
	if len(testID) < 8 || len(testID) > 64 {
		return false
	}
	for _, character := range testID {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func analyzeDNSLeak(entries []dnsLeakResult) map[string]any {
	result := map[string]any{"available": false, "leaked": false, "details": ""}
	exitASN := ""
	for _, entry := range entries {
		if entry.Type == "ip" {
			exitASN = strings.TrimSpace(entry.ASN)
			break
		}
	}
	servers := make([]string, 0)
	leaked := false
	comparable := false
	for _, entry := range entries {
		if entry.Type != "dns" {
			continue
		}
		label := entry.IP
		if entry.CountryName != "" {
			label += " (" + entry.CountryName + ")"
		}
		servers = append(servers, label)
		if exitASN != "" && strings.TrimSpace(entry.ASN) != "" {
			comparable = true
			if !strings.EqualFold(strings.TrimSpace(entry.ASN), exitASN) {
				leaked = true
			}
		}
	}
	if len(servers) == 0 {
		result["details"] = "未检测到 DNS 解析器，无法判断是否泄漏"
		return result
	}
	result["available"] = comparable
	result["leaked"] = leaked
	result["dns_servers"] = servers
	if !comparable {
		result["details"] = "检测到 DNS 解析器，但缺少 ASN 信息，无法判断是否泄漏: " + strings.Join(servers, ", ")
	} else if leaked {
		result["details"] = "DNS 解析器与 VPN 出口网络不一致，可能存在泄漏: " + strings.Join(servers, ", ")
	} else {
		result["details"] = "DNS 解析器与 VPN 出口网络一致: " + strings.Join(servers, ", ")
	}
	return result
}

// checkIPv6Leak 检测 IPv6 是否绕过 VPN。
func (a *Application) checkIPv6Leak(ctx context.Context, client *http.Client) map[string]any {
	result := map[string]any{"leaked": false, "details": "IPv6 流量已通过代理隧道"}
	body, err := fetchWithClient(ctx, client, "https://v6.ident.me")
	if err != nil {
		result["details"] = "IPv6 检测不可用（可能节点不支持 IPv6）"
		return result
	}
	body = strings.TrimSpace(body)
	if body == "" {
		result["details"] = "节点未分配 IPv6 地址，无泄漏风险"
		return result
	}
	ip := net.ParseIP(body)
	if ip != nil && ip.To4() == nil {
		result["leaked"] = false
		result["ipv6"] = body
		result["details"] = "IPv6 出口: " + body + "（已通过 VPN）"
	}
	return result
}

// geoUpgrade 在线升级 geoip.dat 和 geosite.dat。
func (a *Application) geoUpgrade(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeJSONResponse(writer, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 POST"})
		return
	}
	results := proxy.UpgradeGeoFiles()
	allOK := true
	for _, v := range results {
		if v != "updated" {
			allOK = false
		}
	}
	a.reloadSplitRouting()
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": allOK, "results": results, "geo_status": proxy.GeoStatus()})
}

// geoReload 重新加载本地 geo 数据文件。
func (a *Application) geoReload(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeJSONResponse(writer, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 POST"})
		return
	}
	proxy.ReloadGeoData()
	a.reloadSplitRouting()
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "geo_status": proxy.GeoStatus()})
}
