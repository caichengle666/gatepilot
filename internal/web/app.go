package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caichengle666/gatepilot/internal/proxy"
	"github.com/caichengle666/gatepilot/internal/store"
	"github.com/caichengle666/gatepilot/internal/vpn"
)

// Application 是 Web 管理服务。
type Application struct {
	Store             *store.Store
	VPN               *vpn.Controller
	Proxy             *proxy.Server
	startedAt         time.Time
	server            *http.Server
	serverMu          sync.Mutex
	sessionsMu        sync.Mutex
	sessions          map[string]time.Time
	loginMu           sync.Mutex
	logins            map[string]loginFailure
	Operations        operationLock
	speedTests        sync.Mutex
	maintenanceMu     sync.Mutex
	maintenanceCancel context.CancelFunc
	tunnelProxyMu     sync.Mutex
	tunnelProxies     map[string]*proxy.Server
	tunnelFailoverMu  sync.Mutex
	tunnelFailovers   map[string]bool
}

type loginFailure struct {
	count        int
	blockedUntil time.Time
}

type operationLock struct {
	mutex sync.Mutex
}

func (lock *operationLock) TryLock() bool {
	return lock.mutex.TryLock()
}

func (lock *operationLock) TryLockFor(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if lock.TryLock() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (lock *operationLock) Lock() {
	lock.mutex.Lock()
}

func (lock *operationLock) Unlock() {
	lock.mutex.Unlock()
}

func (lock *operationLock) unlockIfOwned() {
	lock.mutex.Unlock()
}

func (a *Application) setMaintenanceCancel(cancel context.CancelFunc) {
	a.maintenanceMu.Lock()
	a.maintenanceCancel = cancel
	a.maintenanceMu.Unlock()
}

func (a *Application) clearMaintenanceCancel() {
	a.maintenanceMu.Lock()
	a.maintenanceCancel = nil
	a.maintenanceMu.Unlock()
}

func (a *Application) cancelMaintenance() {
	a.maintenanceMu.Lock()
	cancel := a.maintenanceCancel
	a.maintenanceMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// NewApplication 创建 Web 管理服务。
func NewApplication(application *store.Store, vpnCtrl *vpn.Controller) *Application {
	webApp := &Application{
		Store: application, VPN: vpnCtrl, startedAt: time.Now(),
		sessions: map[string]time.Time{}, logins: map[string]loginFailure{}, tunnelProxies: map[string]*proxy.Server{}, tunnelFailovers: map[string]bool{},
	}
	vpnCtrl.TunnelStopped = webApp.stopTunnelProxy
	return webApp
}

// Serve 启动 HTTP 监听，端口变更后自动重启。
func (a *Application) Serve() error {
	for {
		ui, _, _ := a.Store.Snapshot()
		address := net.JoinHostPort(ui.Host, strconv.Itoa(ui.Port))
		server := &http.Server{
			Addr: address, Handler: a,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      3 * time.Minute,
			IdleTimeout:       time.Minute,
			MaxHeaderBytes:    1 << 20,
		}
		a.serverMu.Lock()
		a.server = server
		a.serverMu.Unlock()
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (a *Application) restartServer() {
	a.serverMu.Lock()
	server := a.server
	a.serverMu.Unlock()
	if server == nil {
		return
	}
	go server.Shutdown(context.Background())
}

func (a *Application) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthz" {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true})
		return
	}
	ui, _, _ := a.Store.Snapshot()
	if request.URL.Path == "/"+strings.Trim(ui.SecretPath, "/") {
		http.Redirect(writer, request, request.URL.Path+"/", http.StatusFound)
		return
	}
	path, ok := a.effectivePath(request.URL.Path)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	if request.Method == http.MethodPost && path == "/api/login" {
		a.login(writer, request)
		return
	}
	if !a.authorized(request) {
		if request.Method == http.MethodGet && (path == "/" || path == "/index.html") {
			writeHTML(writer, loginHTML)
			return
		}
		writeJSONResponse(writer, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Unauthorized"})
		return
	}
	if request.Method == http.MethodGet {
		a.handleGET(writer, request, path)
		return
	}
	if request.Method == http.MethodPost {
		a.handlePOST(writer, request, path)
		return
	}
	writer.WriteHeader(http.StatusMethodNotAllowed)
}

func (a *Application) effectivePath(path string) (string, bool) {
	ui, _, _ := a.Store.Snapshot()
	prefix := "/" + strings.Trim(ui.SecretPath, "/")
	if strings.HasPrefix(path, prefix+"/") {
		return "/" + strings.TrimPrefix(path, prefix+"/"), true
	}
	return "", false
}

func (a *Application) authorized(request *http.Request) bool {
	cookie, err := request.Cookie("session")
	if err != nil {
		return false
	}
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()
	expires, exists := a.sessions[cookie.Value]
	if !exists || time.Now().After(expires) {
		delete(a.sessions, cookie.Value)
		return false
	}
	return true
}

func (a *Application) login(writer http.ResponseWriter, request *http.Request) {
	clientIP := request.RemoteAddr
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		clientIP = host
	}
	a.loginMu.Lock()
	failure := a.logins[clientIP]
	if time.Now().Before(failure.blockedUntil) {
		a.loginMu.Unlock()
		writeJSONResponse(writer, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "登录失败次数过多，请稍后再试"})
		return
	}
	a.loginMu.Unlock()
	var payload struct{ Username, Password string }
	if err := decodeJSON(request, &payload); err != nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ui, _, _ := a.Store.Snapshot()
	usernameMatch := subtle.ConstantTimeCompare([]byte(payload.Username), []byte(ui.Username))
	passwordMatch := subtle.ConstantTimeCompare([]byte(payload.Password), []byte(ui.Password))
	if usernameMatch&passwordMatch != 1 {
		a.loginMu.Lock()
		failure = a.logins[clientIP]
		failure.count++
		if failure.count >= 5 {
			failure.blockedUntil = time.Now().Add(time.Minute)
		}
		a.logins[clientIP] = failure
		a.loginMu.Unlock()
		writeJSONResponse(writer, http.StatusForbidden, map[string]any{"ok": false, "error": "用户名或密码不正确，请重新输入"})
		return
	}
	a.loginMu.Lock()
	delete(a.logins, clientIP)
	a.loginMu.Unlock()
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeJSONResponse(writer, http.StatusInternalServerError, map[string]any{"ok": false, "error": "无法创建安全会话"})
		return
	}
	token := hex.EncodeToString(tokenBytes)
	a.sessionsMu.Lock()
	a.sessions[token] = time.Now().Add(30 * 24 * time.Hour)
	a.sessionsMu.Unlock()
	cookiePath := "/" + strings.Trim(ui.SecretPath, "/") + "/"
	http.SetCookie(writer, &http.Cookie{Name: "session", Value: token, Path: cookiePath, HttpOnly: true, Secure: request.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 86400})
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true})
}

func (a *Application) handleGET(writer http.ResponseWriter, request *http.Request, path string) {
	switch {
	case path == "/" || path == "/index.html":
		writeHTML(writer, indexHTML)
	case path == "/api/nodes":
		ui, state, nodes := a.Store.Snapshot()
		for index := range nodes {
			nodes[index].ConfigText = ""
		}
		writeJSONResponse(writer, http.StatusOK, map[string]any{"nodes": nodes, "state": statePayload(a.Store.Config, ui, state), "ui_config": publicUIConfig(ui)})
	case path == "/api/gateway_status":
		writeJSONResponse(writer, http.StatusOK, a.gatewayStatus())
	case path == "/api/traffic":
		if a.Proxy == nil {
			writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": false, "error": "本地代理未启动"})
			return
		}
		writeJSONResponse(writer, http.StatusOK, a.Proxy.Traffic())
	case path == "/api/tunnels":
		writeJSONResponse(writer, http.StatusOK, map[string]any{
			"supported": runtime.GOOS == "linux", "max_tunnels": 8, "tunnels": a.VPN.Tunnels(),
		})
	case path == "/api/split_routing":
		a.getSplitRouting(writer, request)
	case path == "/api/logs":
		limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
		writeJSONResponse(writer, http.StatusOK, map[string]any{"logs": a.Store.RecentLogs(limit)})
	case strings.HasPrefix(path, "/configs/"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/configs/"), ".ovpn")
		candidate, found := a.Store.NodeByID(id)
		if !found || candidate.ConfigText == "" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/x-openvpn-profile")
		writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", store.SafeName(candidate.ID)+".ovpn"))
		_, _ = io.WriteString(writer, candidate.ConfigText)
	default:
		http.NotFound(writer, request)
	}
}

func publicUIConfig(ui store.UIConfig) map[string]any {
	return map[string]any{
		"host": ui.Host, "port": ui.Port, "proxy_port": ui.ProxyPort, "upstream_proxy": ui.UpstreamProxy,
		"proxy_auth_enabled": ui.ProxyAuthEnabled, "proxy_username": ui.ProxyUsername, "proxy_password_set": ui.ProxyPassword != "",
		"speed_test_url": ui.SpeedTestURL,
		"routing_mode":   ui.RoutingMode, "force_country": ui.ForceCountry,
		"routing_ip_type": ui.RoutingIPType, "connection_enabled": ui.ConnectionEnabled,
		"fixed_node_id": ui.FixedNodeID, "favorite_node_ids": ui.FavoriteNodeIDs,
		"fav_fail_fallback": ui.FavoriteFallback,
	}
}

func statePayload(config store.AppConfig, ui store.UIConfig, state store.RuntimeState) map[string]any {
	data, _ := json.Marshal(state)
	result := map[string]any{}
	_ = json.Unmarshal(data, &result)
	result["username"] = ui.Username
	result["port"] = ui.Port
	result["secret_path"] = ui.SecretPath
	result["password_set"] = ui.Password != ""
	result["proxy_port"] = ui.ProxyPort
	result["proxy_published_port"] = config.ProxyPublishedPort
	result["proxy_auth_enabled"] = ui.ProxyAuthEnabled
	result["proxy_username"] = ui.ProxyUsername
	result["proxy_password_set"] = ui.ProxyPassword != ""
	result["upstream_proxy"] = ui.UpstreamProxy
	result["speed_test_url"] = ui.SpeedTestURL
	result["routing_mode"] = ui.RoutingMode
	result["force_country"] = ui.ForceCountry
	result["routing_ip_type"] = ui.RoutingIPType
	result["connection_enabled"] = ui.ConnectionEnabled
	result["fixed_node_id"] = ui.FixedNodeID
	result["favorite_node_ids"] = ui.FavoriteNodeIDs
	result["fav_fail_fallback"] = ui.FavoriteFallback
	return result
}

func (a *Application) gatewayStatus() map[string]any {
	ui, state, _ := a.Store.Snapshot()
	proxyAddress := net.JoinHostPort(a.Store.Config.ProxyHost, strconv.Itoa(ui.ProxyPort))
	probeAddress := proxyAddress
	if a.Store.Config.ProxyHost == "::" || a.Store.Config.ProxyHost == "0.0.0.0" {
		probeAddress = net.JoinHostPort("127.0.0.1", strconv.Itoa(ui.ProxyPort))
	}
	connection, proxyError := net.DialTimeout("tcp", probeAddress, 500*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
	}
	service := func(name, status, details, errorMessage string) map[string]string {
		return map[string]string{"name": name, "status": status, "details": details, "error": errorMessage}
	}
	proxyState, proxyMessage := "running", ""
	if proxyError != nil {
		proxyState, proxyMessage = "stopped", proxyError.Error()
	}
	vpnState := "stopped"
	if a.VPN.Running() {
		vpnState = "running"
	}
	now := time.Now()
	uptime := now.Sub(a.startedAt)
	heartbeatService := func(name string, heartbeat int64, allowance time.Duration, startupAllowance time.Duration, stoppedMessage string) map[string]string {
		ok := heartbeat > 0 && now.Sub(time.Unix(heartbeat, 0)) < allowance || uptime < startupAllowance
		status, details, errorMessage := "running", "上次心跳: 等待启动", ""
		if heartbeat > 0 {
			details = "上次心跳: " + time.Unix(heartbeat, 0).Format("2006-01-02 15:04:05")
		}
		if !ok {
			status, errorMessage = "stopped", stoppedMessage
		}
		return service(name, status, details, errorMessage)
	}
	return map[string]any{
		"ok": true,
		"services": []any{
			service("Web 管理服务", "running", net.JoinHostPort(ui.Host, strconv.Itoa(ui.Port)), ""),
			service("本地代理网关", proxyState, proxyAddress, proxyMessage),
			service("OpenVPN 核心连接", vpnState, state.Message, ""),
			heartbeatService("节点同步守护线程", state.CollectorHeartbeat, a.Store.Config.FetchInterval+a.Store.Config.FetchInterval/2, 15*time.Second, "线程可能已异常终止，无法在后台拉取和测速节点"),
			heartbeatService("出口检测守护线程", state.CheckerHeartbeat, 90*time.Second, 35*time.Second, "线程可能已挂起，无法刷新代理出口状态"),
			heartbeatService("延迟测速守护线程", state.PingerHeartbeat, 30*time.Second, 15*time.Second, "线程可能已挂起，无法刷新节点延迟"),
		},
		"uptime_seconds": int64(time.Since(a.startedAt).Seconds()),
	}
}

func (a *Application) handlePOST(writer http.ResponseWriter, request *http.Request, path string) {
	switch path {
	case "/api/logout":
		ui, _, _ := a.Store.Snapshot()
		if cookie, err := request.Cookie("session"); err == nil {
			a.sessionsMu.Lock()
			delete(a.sessions, cookie.Value)
			a.sessionsMu.Unlock()
		}
		cookiePath := "/" + strings.Trim(ui.SecretPath, "/") + "/"
		http.SetCookie(writer, &http.Cookie{Name: "session", Value: "", Path: cookiePath, MaxAge: -1, HttpOnly: true, Secure: request.TLS != nil, SameSite: http.SameSiteLaxMode})
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true})
	case "/api/connect":
		var payload struct {
			ID       string `json:"id"`
			Protocol string `json:"protocol"`
		}
		if err := decodeJSON(request, &payload); err != nil || payload.ID == "" {
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "节点 ID 不能为空"})
			return
		}
		if err := validateConnectProtocol(a.Store, payload.ID, payload.Protocol); err != nil {
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		a.cancelMaintenance()
		if !a.Operations.TryLockFor(8 * time.Second) {
			writeJSONResponse(writer, http.StatusConflict, map[string]any{"ok": false, "error": "当前已有连接或节点维护任务正在运行"})
			return
		}
		message, err := a.VPN.Connect(payload.ID)
		a.Operations.unlockIfOwned()
		writeOperationResult(writer, message, err)
	case "/api/disconnect":
		a.cancelMaintenance()
		a.Store.SetConnectionEnabled(false)
		a.VPN.Stop("用户已断开连接")
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true})
	case "/api/tunnels/connect":
		a.connectTunnel(writer, request)
	case "/api/tunnels/disconnect":
		a.disconnectTunnel(writer, request)
	case "/api/refresh_nodes":
		if !a.Operations.TryLock() {
			writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "message": "节点维护任务正在运行，请稍后再试", "running": true})
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		a.setMaintenanceCancel(cancel)
		go func() {
			defer a.Operations.unlockIfOwned()
			defer cancel()
			defer a.clearMaintenanceCancel()
			_, _ = a.maintainLocked(ctx, true)
		}()
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "message": "已在后台启动节点更新流程", "running": false})
	case "/api/check":
		message, err := a.maintain(request.Context(), true)
		writeOperationResult(writer, message, err)
	case "/api/test_node":
		var payload struct {
			ID string `json:"id"`
		}
		if err := decodeJSON(request, &payload); err != nil || payload.ID == "" {
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "节点 ID 不能为空"})
			return
		}
		if !a.Operations.TryLock() {
			writeJSONResponse(writer, http.StatusConflict, map[string]any{"ok": false, "error": "当前已有连接或节点维护任务正在运行"})
			return
		}
		updated, err := a.VPN.TestNode(payload.ID)
		a.Operations.unlockIfOwned()
		if updated.ID == "" {
			writeOperationResult(writer, "", err)
			return
		}
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "node": updated, "error": errorText(err)})
	case "/api/test_nodes":
		var payload struct {
			IDs []string `json:"ids"`
		}
		if err := decodeJSON(request, &payload); err != nil || len(payload.IDs) > a.Store.Config.ManualTestNodeLimit {
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": fmt.Sprintf("单次最多测试 %d 个节点", a.Store.Config.ManualTestNodeLimit)})
			return
		}
		if !a.Operations.TryLock() {
			writeJSONResponse(writer, http.StatusConflict, map[string]any{"ok": false, "error": "当前已有连接或节点维护任务正在运行"})
			return
		}
		nodes := a.VPN.TestNodes(payload.IDs)
		a.Operations.unlockIfOwned()
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "nodes": nodes})
	case "/api/toggle_favorite":
		var payload struct {
			ID string `json:"id"`
		}
		if err := decodeJSON(request, &payload); err != nil || payload.ID == "" {
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "节点 ID 不能为空"})
			return
		}
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "favorite_node_ids": a.Store.ToggleFavorite(payload.ID)})
	case "/api/update_credentials":
		a.updateCredentials(writer, request)
	case "/api/update_settings", "/api/update_routing":
		a.updateSettings(writer, request)
	case "/api/test_proxy":
		a.testProxy(writer)
	case "/api/dns_leak_check":
		a.dnsLeakCheck(writer, request)
	case "/api/geo/upgrade":
		a.geoUpgrade(writer, request)
	case "/api/geo/reload":
		a.geoReload(writer, request)
	case "/api/speed_test":
		a.speedTest(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (a *Application) connectTunnel(writer http.ResponseWriter, request *http.Request) {
	if runtime.GOOS != "linux" {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "附加 VPN 隧道目前仅支持 Linux"})
		return
	}
	var payload struct {
		ID        string `json:"id"`
		ProxyPort int    `json:"proxy_port"`
	}
	if err := decodeJSON(request, &payload); err != nil || payload.ID == "" {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "节点 ID 不能为空"})
		return
	}
	ui, _, _ := a.Store.Snapshot()
	if payload.ProxyPort == 0 {
		payload.ProxyPort = a.nextTunnelProxyPort(ui)
	}
	portEnd := a.Store.Config.TunnelProxyPortStart + 7
	if payload.ProxyPort < a.Store.Config.TunnelProxyPortStart || payload.ProxyPort > portEnd || payload.ProxyPort == ui.Port || payload.ProxyPort == ui.ProxyPort {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "附加代理端口无效或与现有服务冲突"})
		return
	}
	if !a.Operations.TryLockFor(8 * time.Second) {
		writeJSONResponse(writer, http.StatusConflict, map[string]any{"ok": false, "error": "当前已有连接或节点维护任务正在运行"})
		return
	}
	status, err := a.VPN.ConnectTunnel(request.Context(), payload.ID, payload.ProxyPort)
	a.Operations.unlockIfOwned()
	if err != nil {
		writeOperationResult(writer, "", err)
		return
	}
	if err := a.startTunnelProxy(ui, status); err != nil {
		_ = a.VPN.DisconnectTunnel(status.Device)
		writeOperationResult(writer, "", fmt.Errorf("启动附加代理端口 %d 失败: %w", status.ProxyPort, err))
		return
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "tunnel": status})
}

func (a *Application) disconnectTunnel(writer http.ResponseWriter, request *http.Request) {
	var payload struct {
		Device string `json:"device"`
	}
	if err := decodeJSON(request, &payload); err != nil || !regexp.MustCompile(`^tun[1-8]$`).MatchString(payload.Device) {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "附加隧道设备名无效"})
		return
	}
	if err := a.VPN.DisconnectTunnel(payload.Device); err != nil {
		writeOperationResult(writer, "", err)
		return
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true})
}

func (a *Application) nextTunnelProxyPort(ui store.UIConfig) int {
	used := map[int]bool{ui.Port: true, ui.ProxyPort: true}
	for _, tunnel := range a.VPN.Tunnels() {
		used[tunnel.ProxyPort] = true
	}
	for port := a.Store.Config.TunnelProxyPortStart; port < a.Store.Config.TunnelProxyPortStart+8; port++ {
		if !used[port] {
			return port
		}
	}
	return 0
}

func (a *Application) startTunnelProxy(ui store.UIConfig, status vpn.TunnelStatus) error {
	server := proxy.NewTunnelServer(a.Store.Config, ui, status.ProxyPort, status.Device)
	a.tunnelProxyMu.Lock()
	a.tunnelProxies[status.Device] = server
	a.tunnelProxyMu.Unlock()
	if err := server.Start(); err != nil {
		a.stopTunnelProxy(status, false)
		return err
	}
	return nil
}

func (a *Application) stopTunnelProxy(status vpn.TunnelStatus, unexpected bool) {
	a.tunnelProxyMu.Lock()
	server := a.tunnelProxies[status.Device]
	delete(a.tunnelProxies, status.Device)
	a.tunnelProxyMu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	if unexpected {
		a.scheduleTunnelFailover(status, "附加隧道异常退出")
	}
}

func (a *Application) scheduleTunnelFailover(previous vpn.TunnelStatus, reason string) {
	a.tunnelFailoverMu.Lock()
	if a.tunnelFailovers[previous.Device] {
		a.tunnelFailoverMu.Unlock()
		return
	}
	a.tunnelFailovers[previous.Device] = true
	a.tunnelFailoverMu.Unlock()
	go func() {
		defer func() {
			a.tunnelFailoverMu.Lock()
			delete(a.tunnelFailovers, previous.Device)
			a.tunnelFailoverMu.Unlock()
		}()
		a.failoverTunnel(previous, reason)
	}()
}

func (a *Application) failoverTunnel(previous vpn.TunnelStatus, reason string) {
	if current, found := a.tunnelStatus(previous.Device); found {
		if current.NodeID != previous.NodeID {
			return
		}
		if err := a.VPN.DisconnectTunnel(previous.Device); err != nil {
			a.Store.LogEvent("warning", "VPN", fmt.Sprintf("附加隧道 %s 清理失败: %v", previous.Device, err))
			return
		}
	}
	for _, candidate := range a.Store.Candidates() {
		if candidate.ID == previous.NodeID || candidate.ProbeStatus != "available" {
			continue
		}
		if !a.Operations.TryLockFor(8 * time.Second) {
			return
		}
		status, err := a.VPN.ConnectTunnelOnDevice(context.Background(), candidate.ID, previous.ProxyPort, previous.Device)
		a.Operations.unlockIfOwned()
		if err != nil {
			a.Store.LogEvent("warning", "VPN", fmt.Sprintf("附加隧道 %s 切换节点 %s 失败: %v", previous.Device, candidate.ID, err))
			continue
		}
		ui, _, _ := a.Store.Snapshot()
		if err := a.startTunnelProxy(ui, status); err != nil {
			_ = a.VPN.DisconnectTunnel(status.Device)
			a.Store.LogEvent("warning", "VPN", fmt.Sprintf("附加隧道 %s 恢复代理失败: %v", previous.Device, err))
			continue
		}
		a.Store.LogEvent("info", "VPN", fmt.Sprintf("附加隧道 %s 已自动切换到节点 %s，继续使用代理端口 %d（原因：%s）", previous.Device, candidate.ID, previous.PublishedProxyPort, reason))
		return
	}
	a.Store.LogEvent("error", "VPN", fmt.Sprintf("附加隧道 %s 没有可用备用节点，代理端口 %d 已停止", previous.Device, previous.PublishedProxyPort))
}

func (a *Application) tunnelStatus(device string) (vpn.TunnelStatus, bool) {
	for _, status := range a.VPN.Tunnels() {
		if status.Device == device {
			return status, true
		}
	}
	return vpn.TunnelStatus{}, false
}

func (a *Application) updateTunnelProxyAuth(username, password string) {
	a.tunnelProxyMu.Lock()
	defer a.tunnelProxyMu.Unlock()
	for _, server := range a.tunnelProxies {
		server.UpdateAuth(username, password)
	}
}

func validateConnectProtocol(application *store.Store, nodeID, requested string) error {
	requested = strings.ToLower(strings.TrimSpace(requested))
	if requested == "" {
		return nil
	}
	if requested != "tcp" && requested != "udp" {
		return fmt.Errorf("不支持的连接协议 %q", requested)
	}
	candidate, found := application.NodeByID(nodeID)
	if !found {
		return fmt.Errorf("找不到节点 %s", nodeID)
	}
	if !strings.HasPrefix(strings.ToLower(candidate.Protocol), requested) {
		return fmt.Errorf("节点 %s 不是 %s 节点", nodeID, strings.ToUpper(requested))
	}
	return nil
}

func (a *Application) maintain(ctx context.Context, force bool) (string, error) {
	if !a.Operations.TryLock() {
		return "", errors.New("节点维护任务正在运行")
	}
	ctx, cancel := context.WithCancel(ctx)
	a.setMaintenanceCancel(cancel)
	defer a.Operations.unlockIfOwned()
	defer cancel()
	defer a.clearMaintenanceCancel()
	return a.maintainLocked(ctx, force)
}

func (a *Application) maintainLocked(ctx context.Context, force bool) (string, error) {
	_ = a.Store.UpdateState(func(state *store.RuntimeState) {
		state.MaintenanceRunning = true
		state.IsConnecting = true
		state.LastCheckMessage = "正在维护可用节点"
	})
	defer a.Store.UpdateState(func(state *store.RuntimeState) {
		state.MaintenanceRunning = false
		state.IsConnecting = false
	})
	testedTotal := 0
	for refreshRound := 0; refreshRound < 2; refreshRound++ {
		if refreshRound > 0 {
			_ = a.Store.UpdateState(func(state *store.RuntimeState) {
				state.LastCheckMessage = "连接连续失败，正在重新拉取节点列表"
			})
			a.Store.LogEvent("warning", "Collector", "自动连接连续失败，重新拉取 VPNGate 节点列表")
			if _, err := a.Store.RefreshNodes(ctx); err != nil && len(a.Store.Candidates()) == 0 {
				return "", err
			}
		} else if force || len(a.Store.Candidates()) == 0 {
			if _, err := a.Store.RefreshNodes(ctx); err != nil && len(a.Store.Candidates()) == 0 {
				return "", err
			}
		}

		candidates := a.Store.Candidates()
		valid := 0
		for _, candidate := range candidates {
			if candidate.ProbeStatus == "available" {
				valid++
			}
		}
		ids := make([]string, 0, a.Store.Config.InitialTestLimit)
		for _, candidate := range candidates {
			if valid+len(ids) >= a.Store.Config.TargetValidNodes || len(ids) >= a.Store.Config.InitialTestLimit {
				break
			}
			if candidate.ProbeStatus != "available" {
				ids = append(ids, candidate.ID)
			}
		}
		tested := a.VPN.TestNodesContext(ctx, ids)
		testedTotal += len(tested)
		if err := ctx.Err(); err != nil {
			return "", err
		}
		valid = 0
		for _, candidate := range a.Store.Candidates() {
			if candidate.ProbeStatus == "available" {
				valid++
			}
		}
		_ = a.Store.UpdateState(func(state *store.RuntimeState) {
			state.LastCheckAt = time.Now().Unix()
			state.ValidNodes = valid
			state.LastCheckMessage = fmt.Sprintf("节点维护完成，可用 %d 个", valid)
		})

		ui, _, _ := a.Store.Snapshot()
		if !ui.ConnectionEnabled || a.VPN.Running() {
			return fmt.Sprintf("节点维护完成，测试了 %d 个节点，可用 %d 个", testedTotal, valid), nil
		}
		if ui.RoutingMode == "fixed_ip" && ui.FixedNodeID != "" {
			if message, err := a.VPN.ConnectContext(ctx, ui.FixedNodeID); err == nil {
				return message, nil
			}
		} else {
			attempts := 0
			var lastErr error
			for _, candidate := range a.Store.Candidates() {
				if err := ctx.Err(); err != nil {
					return "", err
				}
				if candidate.ProbeStatus != "available" {
					continue
				}
				attempts++
				if message, err := a.VPN.ConnectContext(ctx, candidate.ID); err == nil {
					return message, nil
				} else {
					lastErr = err
				}
				if attempts >= 3 {
					break
				}
			}
			if refreshRound == 1 && lastErr != nil {
				return "", fmt.Errorf("自动连接连续失败: %w", lastErr)
			}
		}
	}
	return "", errors.New("自动连接失败，等待下一轮节点维护")
}

func (a *Application) updateCredentials(writer http.ResponseWriter, request *http.Request) {
	var payload struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Port       any    `json:"port"`
		SecretPath string `json:"secret_path"`
	}
	if err := decodeJSON(request, &payload); err != nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求参数无效"})
		return
	}
	var reauthRequired, portChanged, restartNeeded bool
	err := a.Store.MutateUI(func(ui *store.UIConfig, _ store.RuntimeState) error {
		username := strings.TrimSpace(payload.Username)
		if username == "" || strings.TrimSpace(payload.Password) == "" && ui.Password == "" {
			return errors.New("用户名不能为空；首次设置时密码不能为空")
		}
		port := ui.Port
		if payload.Port != nil {
			var ok bool
			port, ok = numberFromJSON(payload.Port)
			if !ok || port < 1 || port > 65535 {
				return errors.New("网页管理端口范围必须是 1 至 65535")
			}
		}
		secretPath := strings.TrimSpace(payload.SecretPath)
		if secretPath == "" {
			secretPath = ui.SecretPath
		}
		if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(secretPath) {
			return errors.New("安全后缀仅能由英文字母和数字组成")
		}
		oldUsername, oldPassword, oldPort, oldPath := ui.Username, ui.Password, ui.Port, ui.SecretPath
		ui.Username, ui.Port, ui.SecretPath = username, port, secretPath
		if strings.TrimSpace(payload.Password) != "" {
			ui.Password = strings.TrimSpace(payload.Password)
		}
		reauthRequired = oldUsername != ui.Username || oldPassword != ui.Password
		portChanged = oldPort != ui.Port
		restartNeeded = portChanged || oldPath != ui.SecretPath
		return nil
	})
	if err != nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := a.Store.SaveUI(); err != nil {
		writeOperationResult(writer, "", err)
		return
	}
	if reauthRequired {
		a.sessionsMu.Lock()
		a.sessions = map[string]time.Time{}
		a.sessionsMu.Unlock()
	}
	message := "账号密码配置更新成功，已即时生效！"
	if restartNeeded {
		message = "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."
		if portChanged {
			a.scheduleWebRestart()
		}
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "restart_needed": restartNeeded, "reauth_required": reauthRequired, "message": message})
}

func (a *Application) updateSettings(writer http.ResponseWriter, request *http.Request) {
	payload := map[string]any{}
	if err := decodeJSON(request, &payload); err != nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	var webPortChanged, proxyPortChanged bool
	var proxyPort int
	var proxyAuthChanged bool
	err := a.Store.MutateUI(func(ui *store.UIConfig, state store.RuntimeState) error {
		oldPort, oldProxyPort := ui.Port, ui.ProxyPort
		oldProxyAuthEnabled, oldProxyUsername, oldProxyPassword := ui.ProxyAuthEnabled, ui.ProxyUsername, ui.ProxyPassword
		if value, ok := payload["host"].(string); ok && strings.TrimSpace(value) != "" {
			ui.Host = strings.TrimSpace(value)
		}
		if value, ok := numberFromJSON(payload["port"]); ok && value > 0 && value <= 65535 {
			ui.Port = value
		}
		if raw, exists := payload["proxy_port"]; exists {
			value, ok := numberFromJSON(raw)
			if !ok || value < 1024 || value > 65535 {
				return errors.New("代理出站端口范围必须是 1024 至 65535")
			}
			ui.ProxyPort = value
		}
		if raw, exists := payload["upstream_proxy"]; exists {
			value, ok := raw.(string)
			if !ok {
				return errors.New("前置代理格式无效")
			}
			normalized, normalizeErr := store.NormalizeProxyURL(value)
			if normalizeErr != nil {
				return errors.New("前置代理格式无效: " + normalizeErr.Error())
			}
			ui.UpstreamProxy = normalized
		}
		if raw, exists := payload["speed_test_url"]; exists {
			value, ok := raw.(string)
			if !ok {
				return errors.New("宽带测速网址格式无效")
			}
			normalized, normalizeErr := store.NormalizeSpeedTestURL(value)
			if normalizeErr != nil {
				return errors.New("宽带测速网址格式无效: " + normalizeErr.Error())
			}
			ui.SpeedTestURL = normalized
		}
		if raw, exists := payload["proxy_auth_enabled"]; exists {
			enabled, ok := raw.(bool)
			if !ok {
				return errors.New("代理认证开关格式无效")
			}
			ui.ProxyAuthEnabled = enabled
		}
		if raw, exists := payload["proxy_username"]; exists {
			value, ok := raw.(string)
			if !ok {
				return errors.New("代理认证用户名格式无效")
			}
			ui.ProxyUsername = strings.TrimSpace(value)
		}
		if raw, exists := payload["proxy_password"]; exists {
			value, ok := raw.(string)
			if !ok {
				return errors.New("代理认证密码格式无效")
			}
			if strings.TrimSpace(value) != "" {
				ui.ProxyPassword = value
			}
		}
		if err := store.ValidateProxyAuth(a.Store.Config.ProxyHost, *ui); err != nil {
			return err
		}
		if ui.Port == ui.ProxyPort {
			return errors.New("代理端口不能与网页端口相同")
		}
		if value, ok := payload["routing_mode"].(string); ok {
			valid := value == "auto" || value == "fixed_country" || value == "fixed_region" || value == "fixed_ip" || value == "favorites"
			if !valid {
				return errors.New("无效的路由模式")
			}
			ui.RoutingMode = value
		}
		if value, ok := payload["force_country"].(string); ok {
			ui.ForceCountry = strings.TrimSpace(value)
		}
		if value, ok := payload["fixed_node_id"].(string); ok {
			ui.FixedNodeID = strings.TrimSpace(value)
		}
		if value, ok := payload["routing_ip_type"].(string); ok {
			if value != "all" && value != "residential" && value != "hosting" {
				return errors.New("无效的IP出站类型过滤")
			}
			ui.RoutingIPType = value
		}
		if value, ok := payload["connection_enabled"].(bool); ok {
			ui.ConnectionEnabled = value
		}
		if value, ok := payload["fav_fail_fallback"].(bool); ok {
			ui.FavoriteFallback = value
		}
		if value, ok := payload["split_routing"].(bool); ok {
			ui.SplitRouting = value
		}
		if value, ok := payload["split_default"].(string); ok {
			if value != "direct" && value != "vpn" {
				return errors.New("无效的分流默认动作")
			}
			ui.SplitDefault = value
		}
		if raw, exists := payload["split_rules"]; exists {
			rules, parseErr := parseSplitRules(raw)
			if parseErr != nil {
				return parseErr
			}
			ui.SplitRules = rules
		}
		if ui.RoutingMode == "fixed_region" && ui.ForceCountry == "" {
			return errors.New("启用固定地区前，请先选择一个要锁定的国家")
		}
		if ui.RoutingMode == "fixed_ip" && ui.FixedNodeID == "" {
			ui.FixedNodeID = state.ActiveNodeID
			if ui.FixedNodeID == "" {
				return errors.New("启用固定 IP 前，请先连接一个要锁定的节点")
			}
		}
		if ui.RoutingMode == "favorites" {
			ui.FavoriteFallback = false
		}
		webPortChanged = oldPort != ui.Port
		proxyPortChanged = oldProxyPort != ui.ProxyPort
		proxyPort = ui.ProxyPort
		proxyAuthChanged = oldProxyAuthEnabled != ui.ProxyAuthEnabled || oldProxyUsername != ui.ProxyUsername || oldProxyPassword != ui.ProxyPassword
		return nil
	})
	if err != nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := a.Store.SaveUI(); err != nil {
		writeOperationResult(writer, "", err)
		return
	}
	proxy.SetGeoUpstreamProxy(a.Store.UpstreamProxy())
	a.reloadSplitRouting()
	a.enforceRoutingSettings()
	if proxyAuthChanged && a.Proxy != nil {
		username, password, _ := store.ProxyCredentials(uiSnapshot(a.Store))
		a.Proxy.UpdateAuth(username, password)
		a.updateTunnelProxyAuth(username, password)
	}
	message := "配置更新成功，已即时生效！"
	restartNeeded := webPortChanged || proxyPortChanged
	if restartNeeded {
		message = "配置更新成功，代理出站端口变更，将在 2 秒内重启..."
		if webPortChanged {
			a.scheduleWebRestart()
		}
		if proxyPortChanged && a.Proxy != nil {
			a.Proxy.ScheduleRestart(proxyPort)
		}
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "restart_needed": restartNeeded, "message": message})
}

func parseSplitRules(raw any) ([]store.SplitRule, error) {
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("分流规则格式无效")
	}
	rules := make([]store.SplitRule, 0, len(list))
	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("分流规则条目格式无效")
		}
		kind, _ := entry["kind"].(string)
		value, _ := entry["value"].(string)
		action, _ := entry["action"].(string)
		switch kind {
		case "domain", "keyword", "cidr", "geosite", "geoip":
		default:
			return nil, fmt.Errorf("无效的分流规则类型: %s", kind)
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		if action != "direct" && action != "vpn" {
			return nil, errors.New("无效的分流动作")
		}
		rules = append(rules, store.SplitRule{Kind: kind, Value: strings.TrimSpace(value), Action: action})
	}
	return rules, nil
}
func (a *Application) scheduleWebRestart() {
	if store.EnvBool("AIMILIVPN_NO_AUTO_RESTART", false) {
		return
	}
	go func() {
		time.Sleep(2 * time.Second)
		a.Store.LogEvent("info", "System", "Web listener restarting after configuration change")
		a.restartServer()
	}()
}

func (a *Application) enforceRoutingSettings() {
	ui, state, _ := a.Store.Snapshot()
	if state.ActiveNodeID == "" {
		return
	}
	candidate, found := a.Store.NodeByID(state.ActiveNodeID)
	if !found || a.VPN.ValidateCandidate(candidate) != nil {
		a.Store.LogEvent("warning", "Routing", "当前活动节点不符合更新后的路由规则，已断开")
		a.VPN.Stop("路由规则已更新，当前节点不再符合规则")
		if ui.ConnectionEnabled && ui.RoutingMode != "fixed_ip" {
			go a.autoSwitch(0)
		}
	}
}

func uiSnapshot(application *store.Store) store.UIConfig {
	ui, _, _ := application.Snapshot()
	return ui
}

func numberFromJSON(value any) (int, bool) {
	switch number := value.(type) {
	case float64:
		return int(number), true
	case json.Number:
		parsed, err := strconv.Atoi(number.String())
		return parsed, err == nil
	case string:
		parsed, err := strconv.Atoi(number)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func (a *Application) testProxy(writer http.ResponseWriter) {
	result := a.CheckProxyHealth()
	a.updateProxyState(result)
	writeJSONResponse(writer, http.StatusOK, result)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func decodeJSON(request *http.Request, target any) error {
	if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
		return errors.New("请求必须使用 application/json")
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 256<<10))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("请求 JSON 无效: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("请求 JSON 只能包含一个对象")
	}
	return nil
}

func writeOperationResult(writer http.ResponseWriter, message string, err error) {
	if err != nil {
		writeJSONResponse(writer, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "message": message})
}

func writeJSONResponse(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeHTML(writer http.ResponseWriter, value string) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(writer, value)
}
