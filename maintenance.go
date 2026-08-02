package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func backgroundMaintenance(application *webApplication) {
	go application.proxyChecker()
	go application.activeNodePinger()
	application.collectorLoop()
}

func (application *webApplication) collectorLoop() {
	time.Sleep(2 * time.Second)
	nextRefresh := time.Time{}
	for {
		now := time.Now()
		_ = application.store.updateState(func(state *runtimeState) { state.CollectorHeartbeat = now.Unix() })
		if nextRefresh.IsZero() || !now.Before(nextRefresh) {
			if _, err := application.maintain(context.Background(), true); err != nil {
				application.store.logEvent("error", "Collector", "节点刷新维护失败: "+err.Error())
				nextRefresh = now.Add(time.Minute)
			} else {
				nextRefresh = now.Add(application.store.config.FetchInterval)
			}
		} else {
			ui, _, nodes := application.store.snapshot()
			if ui.ConnectionEnabled && !application.vpn.running() && len(nodes) > 0 {
				if _, err := application.maintain(context.Background(), false); err != nil {
					application.store.logEvent("warning", "Collector", "自动连接失败: "+err.Error())
				}
			}
		}
		time.Sleep(application.store.config.ReconnectInterval)
	}
}

func (application *webApplication) autoSwitch(attempt int) {
	if attempt >= 3 {
		application.store.logEvent("error", "VPN", "连续自动切换失败 3 次，等待后台重新获取节点")
		return
	}
	ui, state, _ := application.store.snapshot()
	if !ui.ConnectionEnabled {
		return
	}
	if ui.RoutingMode == "fixed_ip" {
		if ui.FixedNodeID == "" || application.vpn.running() {
			return
		}
		if !application.operations.TryLock() {
			return
		}
		_, err := application.vpn.connect(ui.FixedNodeID)
		application.operations.Unlock()
		if err != nil {
			application.store.logEvent("warning", "VPN", "固定节点重连失败: "+err.Error())
		}
		return
	}
	for _, candidate := range application.store.candidates() {
		if candidate.ID == state.ActiveNodeID || candidate.ProbeStatus != "available" {
			continue
		}
		if !application.operations.TryLock() {
			return
		}
		_, err := application.vpn.connect(candidate.ID)
		application.operations.Unlock()
		if err == nil {
			return
		}
		application.store.logEvent("warning", "VPN", fmt.Sprintf("切换节点 %s 失败: %v", candidate.ID, err))
		attempt++
		if attempt >= 3 {
			return
		}
	}
	application.vpn.stop("没有符合规则的可用备用节点")
}

func (application *webApplication) proxyChecker() {
	time.Sleep(30 * time.Second)
	for {
		_ = application.store.updateState(func(state *runtimeState) { state.CheckerHeartbeat = time.Now().Unix() })
		_, state, _ := application.store.snapshot()
		if !state.IsConnecting {
			result := application.checkProxyHealth()
			application.updateProxyState(result)
			if ok, _ := result["ok"].(bool); !ok && application.vpn.running() {
				_, state, _ := application.store.snapshot()
				if candidate, found := application.store.nodeByID(state.ActiveNodeID); found {
					application.store.markBlacklisted(candidate, fmt.Sprint(result["error"]))
				}
				application.vpn.stop("代理出口健康检查失败")
				go application.autoSwitch(0)
			}
		}
		time.Sleep(30 * time.Second)
	}
}

func (application *webApplication) activeNodePinger() {
	for {
		_ = application.store.updateState(func(state *runtimeState) { state.PingerHeartbeat = time.Now().Unix() })
		_, state, _ := application.store.snapshot()
		latencyText := "无活动连接"
		if application.vpn.running() && state.ActiveNodeID != "" {
			if candidate, found := application.store.nodeByID(state.ActiveNodeID); found {
				latency := measureNodeLatency(candidate, 5*time.Second)
				if latency > 0 {
					latencyText = fmt.Sprintf("%d ms", latency)
				} else {
					latencyText = "检测超时"
				}
			}
		} else if state.IsConnecting {
			latencyText = "测试中..."
		}
		_ = application.store.updateState(func(state *runtimeState) { state.ActiveNodeLatency = latencyText })
		time.Sleep(10 * time.Second)
	}
}

func (application *webApplication) checkProxyHealth() map[string]any {
	ui, _, _ := application.store.snapshot()
	proxyURL := &url.URL{
		Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(ui.ProxyPort)),
	}
	proxyUser := envString("LOCAL_PROXY_USER", getenv("LOCAL_PROXY_USERNAME"))
	proxyPassword := envString("LOCAL_PROXY_PASS", getenv("LOCAL_PROXY_PASSWORD"))
	if proxyUser != "" || proxyPassword != "" {
		proxyURL.User = url.UserPassword(proxyUser, proxyPassword)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	var lastError error
	for _, endpoint := range []string{"https://api.ipify.org?format=json", "https://api.ip.sb/ip"} {
		started := time.Now()
		response, err := client.Get(endpoint)
		if err != nil {
			lastError = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			lastError = fmt.Errorf("%s", response.Status)
			continue
		}
		ip := strings.TrimSpace(string(body))
		var payload map[string]any
		if json.Unmarshal(body, &payload) == nil {
			ip = fmt.Sprint(payload["ip"])
		}
		return map[string]any{"ok": true, "ip": ip, "latency_ms": time.Since(started).Milliseconds()}
	}
	errorMessage := "出口连接测试失败"
	if lastError != nil {
		errorMessage += ": " + lastError.Error()
	}
	if diagnosis := localObstructionDiagnosis(application.store.config); diagnosis != "" {
		errorMessage += " | 本机诊断: " + diagnosis
	}
	return map[string]any{"ok": false, "ip": "-", "latency_ms": int64(0), "error": errorMessage}
}

func (application *webApplication) checkDownloadSpeed() map[string]any {
	ui, _, _ := application.store.snapshot()
	proxyURL := &url.URL{
		Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(ui.ProxyPort)),
	}
	proxyUser := envString("LOCAL_PROXY_USER", getenv("LOCAL_PROXY_USERNAME"))
	proxyPassword := envString("LOCAL_PROXY_PASS", getenv("LOCAL_PROXY_PASSWORD"))
	if proxyUser != "" || proxyPassword != "" {
		proxyURL.User = url.UserPassword(proxyUser, proxyPassword)
	}
	request, err := http.NewRequest(http.MethodGet, ui.SpeedTestURL, nil)
	if err != nil {
		return map[string]any{"ok": false, "error": "测速请求无效: " + err.Error()}
	}
	request.Header.Set("User-Agent", "gatepilot-speed-test/1.0")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache")
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return map[string]any{"ok": false, "error": "宽带测速失败: " + err.Error()}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return map[string]any{"ok": false, "error": "测速服务返回 " + response.Status}
	}
	bytesRead, err := io.Copy(io.Discard, io.LimitReader(response.Body, 20<<20))
	if err != nil {
		return map[string]any{"ok": false, "error": "读取测速数据失败: " + err.Error()}
	}
	if bytesRead < 256<<10 {
		return map[string]any{"ok": false, "error": "测速文件太小，至少需要 256 KB"}
	}
	elapsed := time.Since(started)
	if elapsed <= 0 {
		return map[string]any{"ok": false, "error": "测速耗时无效"}
	}
	speedMbps := float64(bytesRead*8) / elapsed.Seconds() / 1_000_000
	return map[string]any{
		"ok": true, "speed_mbps": speedMbps, "bytes": bytesRead,
		"duration_ms": elapsed.Milliseconds(), "url": ui.SpeedTestURL,
	}
}

func (application *webApplication) updateProxyState(result map[string]any) {
	ok, _ := result["ok"].(bool)
	ip := fmt.Sprint(result["ip"])
	latency, _ := result["latency_ms"].(int64)
	errorMessage := ""
	if !ok {
		errorMessage = fmt.Sprint(result["error"])
	}
	_ = application.store.updateState(func(state *runtimeState) {
		state.ProxyOK = ok
		state.ProxyIP = ip
		state.ProxyLatencyMS = latency
		state.ProxyError = errorMessage
	})
}
