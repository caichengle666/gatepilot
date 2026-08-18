package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/caichengle666/gatepilot/internal/store"
	"github.com/caichengle666/gatepilot/internal/vpn"
)

const maxSpeedTestBytes int64 = 20_000_000

type speedTestResult struct {
	OK         bool    `json:"ok"`
	URL        string  `json:"url"`
	Bytes      int64   `json:"bytes"`
	DurationMS int64   `json:"duration_ms"`
	Mbps       float64 `json:"mbps"`
	LimitBytes int64   `json:"limit_bytes"`
}

// BackgroundMaintenance 启动所有后台维护协程。
func BackgroundMaintenance(application *Application) {
	go application.proxyChecker()
	go application.activeNodePinger()
	go application.tunnelHealthChecker()
	application.collectorLoop()
}

func (a *Application) tunnelHealthChecker() {
	time.Sleep(10 * time.Second)
	for {
		for _, status := range a.VPN.Tunnels() {
			go a.checkTunnelHealth(status)
		}
		time.Sleep(20 * time.Second)
	}
}

func (a *Application) checkTunnelHealth(status vpn.TunnelStatus) {
	client := a.proxyHTTPClientForPort(status.ProxyPort, 15*time.Second)
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
		a.VPN.UpdateTunnelHealth(status.Device, true, ip, "代理出口正常", time.Since(started).Milliseconds())
		return
	}

	message := "代理端口检测失败"
	if lastError != nil {
		message += ": " + lastError.Error()
	}
	a.VPN.UpdateTunnelHealth(status.Device, false, "", message, 0)
	current, found := a.tunnelStatus(status.Device)
	if found && current.HealthFailures >= 3 {
		a.scheduleTunnelFailover(current, message)
	}
}

func (a *Application) collectorLoop() {
	time.Sleep(2 * time.Second)
	nextRefresh := time.Time{}
	for {
		now := time.Now()
		_ = a.Store.UpdateState(func(state *store.RuntimeState) { state.CollectorHeartbeat = now.Unix() })
		if nextRefresh.IsZero() || !now.Before(nextRefresh) {
			if _, err := a.maintain(context.Background(), true); err != nil {
				a.Store.LogEvent("error", "Collector", "节点刷新维护失败: "+err.Error())
				nextRefresh = now.Add(time.Minute)
			} else {
				nextRefresh = now.Add(a.Store.Config.FetchInterval)
			}
		} else {
			ui, _, nodes := a.Store.Snapshot()
			if ui.ConnectionEnabled && !a.VPN.Running() && len(nodes) > 0 {
				if _, err := a.maintain(context.Background(), false); err != nil {
					a.Store.LogEvent("warning", "Collector", "自动连接失败: "+err.Error())
				}
			}
		}
		time.Sleep(a.Store.Config.ReconnectInterval)
	}
}

// TriggerAutoSwitch 由代理故障追踪器调用，触发自动切换节点。
func (a *Application) TriggerAutoSwitch(failures int) {
	a.Store.LogEvent("warning", "Proxy", fmt.Sprintf("代理连续出站失败 %d 次，自动切换节点", failures))
	a.autoSwitch(0)
}

func (a *Application) autoSwitch(attempt int) {
	if attempt >= 3 {
		a.Store.LogEvent("error", "VPN", "连续自动切换失败 3 次，等待后台重新获取节点")
		a.retryAfterAutoSwitchFailure()
		return
	}
	ui, state, _ := a.Store.Snapshot()
	if !ui.ConnectionEnabled {
		return
	}
	if ui.RoutingMode == "fixed_ip" {
		if ui.FixedNodeID == "" || a.VPN.Running() {
			return
		}
		if !a.Operations.TryLock() {
			return
		}
		_, err := a.VPN.Connect(ui.FixedNodeID)
		a.Operations.unlockIfOwned()
		if err != nil {
			a.Store.LogEvent("warning", "VPN", "固定节点重连失败: "+err.Error())
			a.retryAfterAutoSwitchFailure()
		}
		return
	}
	for _, candidate := range a.Store.Candidates() {
		ui, _, _ = a.Store.Snapshot()
		if !ui.ConnectionEnabled {
			return
		}
		if candidate.ID == state.ActiveNodeID || candidate.ProbeStatus != "available" {
			continue
		}
		if attempt >= 2 && strings.HasPrefix(strings.ToLower(candidate.Protocol), "udp") {
			continue
		}
		if !a.Operations.TryLock() {
			return
		}
		_, err := a.VPN.Connect(candidate.ID)
		a.Operations.unlockIfOwned()
		if err == nil {
			return
		}
		a.Store.LogEvent("warning", "VPN", fmt.Sprintf("切换节点 %s 失败: %v", candidate.ID, err))
		attempt++
		if attempt >= 3 {
			a.retryAfterAutoSwitchFailure()
			return
		}
	}
	a.VPN.Stop("没有符合规则的可用备用节点")
	a.retryAfterAutoSwitchFailure()
}

func (a *Application) retryAfterAutoSwitchFailure() {
	ui, _, _ := a.Store.Snapshot()
	if !ui.ConnectionEnabled || a.Store.Config.DisableBackground {
		return
	}
	if _, err := a.maintain(context.Background(), false); err != nil {
		a.Store.LogEvent("warning", "VPN", "自动切换后刷新节点并重连失败: "+err.Error())
	}
}

func (a *Application) proxyChecker() {
	time.Sleep(30 * time.Second)
	for {
		_ = a.Store.UpdateState(func(state *store.RuntimeState) { state.CheckerHeartbeat = time.Now().Unix() })
		_, state, _ := a.Store.Snapshot()
		if !state.IsConnecting {
			result := a.CheckProxyHealth()
			a.updateProxyState(result)
			if ok, _ := result["ok"].(bool); !ok && a.VPN.Running() {
				errorMessage := fmt.Sprint(result["error"])
				if !isLocalProxyEnvironmentFailure(errorMessage) {
					_, state, _ := a.Store.Snapshot()
					if candidate, found := a.Store.NodeByID(state.ActiveNodeID); found {
						a.Store.MarkBlacklisted(candidate, errorMessage)
					}
					a.VPN.Stop("代理出口健康检查失败")
					go a.autoSwitch(0)
				} else {
					a.Store.LogEvent("warning", "VPN", "代理出口健康检查失败，但属于本机环境/路由问题，不切换节点: "+errorMessage)
				}
			}
		}
		time.Sleep(30 * time.Second)
	}
}

func isLocalProxyEnvironmentFailure(message string) bool {
	lower := strings.ToLower(message)
	markers := []string{
		"adapter is not ready",
		"openvpn windows adapter",
		"虚拟网卡未就绪",
		"本地代理端口未监听",
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func (a *Application) activeNodePinger() {
	for {
		_ = a.Store.UpdateState(func(state *store.RuntimeState) { state.PingerHeartbeat = time.Now().Unix() })
		_, state, _ := a.Store.Snapshot()
		latencyText := "无活动连接"
		if a.VPN.Running() && state.ActiveNodeID != "" {
			if candidate, found := a.Store.NodeByID(state.ActiveNodeID); found {
				latency := vpn.MeasureNodeLatency(candidate, 5*time.Second)
				if latency > 0 {
					latencyText = fmt.Sprintf("%d ms", latency)
				} else {
					latencyText = "检测超时"
				}
			}
		} else if state.IsConnecting {
			latencyText = "测试中..."
		}
		_ = a.Store.UpdateState(func(state *store.RuntimeState) { state.ActiveNodeLatency = latencyText })
		time.Sleep(10 * time.Second)
	}
}

// CheckProxyHealth 通过本地代理检测出口连通性。
func (a *Application) CheckProxyHealth() map[string]any {
	client := a.proxyHTTPClient(15 * time.Second)
	var lastError error
	for _, endpoint := range []string{"https://api.ipify.org?format=json", "https://api.ip.sb/ip"} {
		started := time.Now()
		response, err := client.Get(endpoint)
		if err != nil {
			lastError = err
			if a.Proxy != nil && a.Proxy.LastDialError() != "" {
				lastError = errors.New(a.Proxy.LastDialError())
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			lastError = fmt.Errorf("%s", response.Status)
			if a.Proxy != nil && a.Proxy.LastDialError() != "" {
				lastError = errors.New(a.Proxy.LastDialError())
			}
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
	if diagnosis := store.LocalObstructionDiagnosis(a.Store.Config); diagnosis != "" {
		errorMessage += " | 本机诊断: " + diagnosis
	}
	return map[string]any{"ok": false, "ip": "-", "latency_ms": int64(0), "error": errorMessage}
}

func (a *Application) proxyHTTPClient(timeout time.Duration) *http.Client {
	ui, _, _ := a.Store.Snapshot()
	return a.proxyHTTPClientForPort(ui.ProxyPort, timeout)
}

func (a *Application) proxyHTTPClientForPort(port int, timeout time.Duration) *http.Client {
	ui, _, _ := a.Store.Snapshot()
	proxyURL := &url.URL{
		Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
	}
	proxyUser, proxyPassword, enabled := store.ProxyCredentials(ui)
	if enabled {
		proxyURL.User = url.UserPassword(proxyUser, proxyPassword)
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
}

func (a *Application) speedTest(writer http.ResponseWriter, request *http.Request) {
	if !a.speedTests.TryLock() {
		writeJSONResponse(writer, http.StatusConflict, map[string]any{"ok": false, "error": "宽带测速正在运行，请稍后再试"})
		return
	}
	defer a.speedTests.Unlock()
	var payload struct {
		URL string `json:"url"`
	}
	if err := decodeJSON(request, &payload); err != nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ui, _, _ := a.Store.Snapshot()
	endpoint := strings.TrimSpace(payload.URL)
	if endpoint == "" {
		endpoint = ui.SpeedTestURL
	}
	normalized, err := store.NormalizeSpeedTestURL(endpoint)
	if err != nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "宽带测速网址格式无效: " + err.Error()})
		return
	}
	result, err := measureDownload(request.Context(), a.proxyHTTPClient(2*time.Minute), normalized, maxSpeedTestBytes)
	if err != nil {
		writeJSONResponse(writer, http.StatusBadGateway, map[string]any{"ok": false, "error": "宽带测速失败: " + err.Error()})
		return
	}
	writeJSONResponse(writer, http.StatusOK, result)
}

func measureDownload(ctx context.Context, client *http.Client, endpoint string, limit int64) (speedTestResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return speedTestResult{}, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return speedTestResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return speedTestResult{}, fmt.Errorf("测速服务器返回 %s", response.Status)
	}
	started := time.Now()
	bytesRead, readErr := io.CopyN(io.Discard, response.Body, limit)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return speedTestResult{}, readErr
	}
	if bytesRead == 0 {
		return speedTestResult{}, errors.New("测速服务器未返回数据")
	}
	duration := time.Since(started)
	if duration <= 0 {
		duration = time.Nanosecond
	}
	return speedTestResult{
		OK:         true,
		URL:        endpoint,
		Bytes:      bytesRead,
		DurationMS: duration.Milliseconds(),
		Mbps:       float64(bytesRead) * 8 / duration.Seconds() / 1_000_000,
		LimitBytes: limit,
	}, nil
}

func (a *Application) updateProxyState(result map[string]any) {
	ok, _ := result["ok"].(bool)
	ip := fmt.Sprint(result["ip"])
	latency, _ := result["latency_ms"].(int64)
	errorMessage := ""
	if !ok {
		errorMessage = fmt.Sprint(result["error"])
	}
	_ = a.Store.UpdateState(func(state *store.RuntimeState) {
		state.ProxyOK = ok
		state.ProxyIP = ip
		state.ProxyLatencyMS = latency
		state.ProxyError = errorMessage
	})
}
