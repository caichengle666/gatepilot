package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type webApplication struct {
	store      *store
	vpn        *vpnController
	startedAt  time.Time
	sessionsMu sync.Mutex
	sessions   map[string]time.Time
	operations sync.Mutex
}

func newWebApplication(application *store, vpn *vpnController) *webApplication {
	return &webApplication{store: application, vpn: vpn, startedAt: time.Now(), sessions: map[string]time.Time{}}
}

func (application *webApplication) serve() error {
	ui, _, _ := application.store.snapshot()
	address := net.JoinHostPort(ui.Host, strconv.Itoa(ui.Port))
	server := &http.Server{Addr: address, Handler: application, ReadHeaderTimeout: 10 * time.Second}
	return server.ListenAndServe()
}

func (application *webApplication) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ui, _, _ := application.store.snapshot()
	if request.URL.Path == "/"+strings.Trim(ui.SecretPath, "/") {
		http.Redirect(writer, request, request.URL.Path+"/", http.StatusFound)
		return
	}
	path, ok := application.effectivePath(request.URL.Path)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	if request.Method == http.MethodPost && path == "/api/login" {
		application.login(writer, request)
		return
	}
	if !application.authorized(request) {
		if request.Method == http.MethodGet && (path == "/" || path == "/index.html") {
			writeHTML(writer, loginHTML)
			return
		}
		writeJSONResponse(writer, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Unauthorized"})
		return
	}
	if request.Method == http.MethodGet {
		application.handleGET(writer, request, path)
		return
	}
	if request.Method == http.MethodPost {
		application.handlePOST(writer, request, path)
		return
	}
	writer.WriteHeader(http.StatusMethodNotAllowed)
}

func (application *webApplication) effectivePath(path string) (string, bool) {
	ui, _, _ := application.store.snapshot()
	prefix := "/" + strings.Trim(ui.SecretPath, "/")
	if strings.HasPrefix(path, prefix+"/") {
		return "/" + strings.TrimPrefix(path, prefix+"/"), true
	}
	return "", false
}

func (application *webApplication) authorized(request *http.Request) bool {
	cookie, err := request.Cookie("session")
	if err != nil {
		return false
	}
	application.sessionsMu.Lock()
	defer application.sessionsMu.Unlock()
	expires, exists := application.sessions[cookie.Value]
	if !exists || time.Now().After(expires) {
		delete(application.sessions, cookie.Value)
		return false
	}
	return true
}

func (application *webApplication) login(writer http.ResponseWriter, request *http.Request) {
	var payload struct{ Username, Password string }
	if err := decodeJSON(request, &payload); err != nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ui, _, _ := application.store.snapshot()
	if payload.Username != ui.Username || payload.Password != ui.Password {
		writeJSONResponse(writer, http.StatusForbidden, map[string]any{"ok": false, "error": "用户名或密码不正确，请重新输入"})
		return
	}
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	application.sessionsMu.Lock()
	application.sessions[token] = time.Now().Add(30 * 24 * time.Hour)
	application.sessionsMu.Unlock()
	cookiePath := "/" + strings.Trim(ui.SecretPath, "/") + "/"
	http.SetCookie(writer, &http.Cookie{Name: "session", Value: token, Path: cookiePath, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 86400})
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true})
}

func (application *webApplication) handleGET(writer http.ResponseWriter, request *http.Request, path string) {
	switch {
	case path == "/" || path == "/index.html":
		writeHTML(writer, indexHTML)
	case path == "/api/nodes":
		ui, state, nodes := application.store.snapshot()
		for index := range nodes {
			nodes[index].ConfigText = ""
		}
		writeJSONResponse(writer, http.StatusOK, map[string]any{"nodes": nodes, "state": statePayload(ui, state), "ui_config": publicUIConfig(ui)})
	case path == "/api/gateway_status":
		writeJSONResponse(writer, http.StatusOK, application.gatewayStatus())
	case path == "/api/logs":
		limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
		writeJSONResponse(writer, http.StatusOK, map[string]any{"logs": application.store.recentLogs(limit)})
	case strings.HasPrefix(path, "/configs/"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/configs/"), ".ovpn")
		candidate, found := application.store.nodeByID(id)
		if !found || candidate.ConfigText == "" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/x-openvpn-profile")
		writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeName(candidate.ID)+".ovpn"))
		_, _ = io.WriteString(writer, candidate.ConfigText)
	default:
		http.NotFound(writer, request)
	}
}

func publicUIConfig(ui uiConfig) map[string]any {
	return map[string]any{
		"host": ui.Host, "port": ui.Port, "proxy_port": ui.ProxyPort,
		"routing_mode": ui.RoutingMode, "force_country": ui.ForceCountry,
		"routing_ip_type": ui.RoutingIPType, "connection_enabled": ui.ConnectionEnabled,
		"fixed_node_id": ui.FixedNodeID, "favorite_node_ids": ui.FavoriteNodeIDs,
		"fav_fail_fallback": ui.FavoriteFallback,
	}
}

func statePayload(ui uiConfig, state runtimeState) map[string]any {
	data, _ := json.Marshal(state)
	result := map[string]any{}
	_ = json.Unmarshal(data, &result)
	result["username"] = ui.Username
	result["port"] = ui.Port
	result["secret_path"] = ui.SecretPath
	result["password_set"] = ui.Password != ""
	result["proxy_port"] = ui.ProxyPort
	result["routing_mode"] = ui.RoutingMode
	result["force_country"] = ui.ForceCountry
	result["routing_ip_type"] = ui.RoutingIPType
	result["connection_enabled"] = ui.ConnectionEnabled
	result["fixed_node_id"] = ui.FixedNodeID
	result["favorite_node_ids"] = ui.FavoriteNodeIDs
	result["fav_fail_fallback"] = ui.FavoriteFallback
	return result
}

func (application *webApplication) gatewayStatus() map[string]any {
	ui, state, _ := application.store.snapshot()
	proxyAddress := net.JoinHostPort(application.store.config.ProxyHost, strconv.Itoa(ui.ProxyPort))
	probeAddress := proxyAddress
	if application.store.config.ProxyHost == "::" || application.store.config.ProxyHost == "0.0.0.0" {
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
	if application.vpn.running() {
		vpnState = "running"
	}
	now := time.Now()
	uptime := now.Sub(application.startedAt)
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
			heartbeatService("节点同步守护线程", state.CollectorHeartbeat, application.store.config.FetchInterval+application.store.config.FetchInterval/2, 15*time.Second, "线程可能已异常终止，无法在后台拉取和测速节点"),
			heartbeatService("出口检测守护线程", state.CheckerHeartbeat, 90*time.Second, 35*time.Second, "线程可能已挂起，无法刷新代理出口状态"),
			heartbeatService("延迟测速守护线程", state.PingerHeartbeat, 30*time.Second, 15*time.Second, "线程可能已中止，无法刷新活动节点延迟"),
		},
		"uptime_seconds": int64(time.Since(application.startedAt).Seconds()),
	}
}

func (application *webApplication) handlePOST(writer http.ResponseWriter, request *http.Request, path string) {
	switch path {
	case "/api/logout":
		if cookie, err := request.Cookie("session"); err == nil {
			application.sessionsMu.Lock()
			delete(application.sessions, cookie.Value)
			application.sessionsMu.Unlock()
		}
		http.SetCookie(writer, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true})
	case "/api/connect":
		var payload struct {
			ID string `json:"id"`
		}
		if err := decodeJSON(request, &payload); err != nil || payload.ID == "" {
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "节点 ID 不能为空"})
			return
		}
		if !application.operations.TryLock() {
			writeJSONResponse(writer, http.StatusConflict, map[string]any{"ok": false, "error": "当前已有连接或节点维护任务正在运行"})
			return
		}
		message, err := application.vpn.connect(payload.ID)
		application.operations.Unlock()
		writeOperationResult(writer, message, err)
	case "/api/disconnect":
		application.store.mu.Lock()
		application.store.ui.ConnectionEnabled = false
		application.store.mu.Unlock()
		_ = application.store.saveUI()
		application.vpn.stop("用户已断开连接")
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true})
	case "/api/refresh_nodes":
		if !application.operations.TryLock() {
			writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "message": "节点维护任务正在运行，请稍后再试", "running": true})
			return
		}
		go func() {
			defer application.operations.Unlock()
			_, _ = application.maintainLocked(context.Background(), true)
		}()
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "message": "已在后台启动节点更新流程", "running": false})
	case "/api/check":
		message, err := application.maintain(request.Context(), true)
		writeOperationResult(writer, message, err)
	case "/api/test_node":
		var payload struct {
			ID string `json:"id"`
		}
		if err := decodeJSON(request, &payload); err != nil || payload.ID == "" {
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "节点 ID 不能为空"})
			return
		}
		if !application.operations.TryLock() {
			writeJSONResponse(writer, http.StatusConflict, map[string]any{"ok": false, "error": "当前已有连接或节点维护任务正在运行"})
			return
		}
		updated, err := application.vpn.testNode(payload.ID)
		application.operations.Unlock()
		if updated.ID == "" {
			writeOperationResult(writer, "", err)
			return
		}
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "node": updated, "error": errorText(err)})
	case "/api/test_nodes":
		var payload struct {
			IDs []string `json:"ids"`
		}
		if err := decodeJSON(request, &payload); err != nil || len(payload.IDs) > application.store.config.ManualTestNodeLimit {
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": fmt.Sprintf("单次最多测试 %d 个节点", application.store.config.ManualTestNodeLimit)})
			return
		}
		if !application.operations.TryLock() {
			writeJSONResponse(writer, http.StatusConflict, map[string]any{"ok": false, "error": "当前已有连接或节点维护任务正在运行"})
			return
		}
		nodes := application.vpn.testNodes(payload.IDs)
		application.operations.Unlock()
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "nodes": nodes})
	case "/api/toggle_favorite":
		var payload struct {
			ID string `json:"id"`
		}
		if err := decodeJSON(request, &payload); err != nil || payload.ID == "" {
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "节点 ID 不能为空"})
			return
		}
		writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "favorite_node_ids": application.store.toggleFavorite(payload.ID)})
	case "/api/update_credentials":
		application.updateCredentials(writer, request)
	case "/api/update_settings", "/api/update_routing":
		application.updateSettings(writer, request)
	case "/api/test_proxy":
		application.testProxy(writer)
	default:
		http.NotFound(writer, request)
	}
}

func (application *webApplication) maintain(ctx context.Context, force bool) (string, error) {
	if !application.operations.TryLock() {
		return "", errors.New("节点维护任务正在运行")
	}
	defer application.operations.Unlock()
	return application.maintainLocked(ctx, force)
}

func (application *webApplication) maintainLocked(ctx context.Context, force bool) (string, error) {
	_ = application.store.updateState(func(state *runtimeState) {
		state.MaintenanceRunning = true
		state.IsConnecting = true
		state.LastCheckMessage = "正在维护可用节点"
	})
	defer application.store.updateState(func(state *runtimeState) {
		state.MaintenanceRunning = false
		state.IsConnecting = false
	})
	if force || len(application.store.candidates()) == 0 {
		if _, err := application.store.refreshNodes(ctx); err != nil && len(application.store.candidates()) == 0 {
			return "", err
		}
	}
	candidates := application.store.candidates()
	valid := 0
	for _, candidate := range candidates {
		if candidate.ProbeStatus == "available" {
			valid++
		}
	}
	ids := make([]string, 0, application.store.config.InitialTestLimit)
	for _, candidate := range candidates {
		if valid+len(ids) >= application.store.config.TargetValidNodes || len(ids) >= application.store.config.InitialTestLimit {
			break
		}
		if candidate.ProbeStatus != "available" {
			ids = append(ids, candidate.ID)
		}
	}
	tested := application.vpn.testNodes(ids)
	valid = 0
	for _, candidate := range application.store.candidates() {
		if candidate.ProbeStatus == "available" {
			valid++
		}
	}
	_ = application.store.updateState(func(state *runtimeState) {
		state.LastCheckAt = time.Now().Unix()
		state.ValidNodes = valid
		state.LastCheckMessage = fmt.Sprintf("节点维护完成，可用 %d 个", valid)
	})
	ui, _, _ := application.store.snapshot()
	if ui.ConnectionEnabled && !application.vpn.running() {
		if ui.RoutingMode == "fixed_ip" && ui.FixedNodeID != "" {
			return application.vpn.connect(ui.FixedNodeID)
		}
		for _, candidate := range application.store.candidates() {
			if candidate.ProbeStatus != "available" {
				continue
			}
			if message, err := application.vpn.connect(candidate.ID); err == nil {
				return message, nil
			}
		}
	}
	return fmt.Sprintf("节点维护完成，测试了 %d 个节点，可用 %d 个", len(tested), valid), nil
}

func (application *webApplication) updateCredentials(writer http.ResponseWriter, request *http.Request) {
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
	application.store.mu.Lock()
	ui := &application.store.ui
	username := strings.TrimSpace(payload.Username)
	if username == "" || strings.TrimSpace(payload.Password) == "" && ui.Password == "" {
		application.store.mu.Unlock()
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "用户名不能为空；首次设置时密码不能为空"})
		return
	}
	port := ui.Port
	if payload.Port != nil {
		var ok bool
		port, ok = numberFromJSON(payload.Port)
		if !ok || port < 1 || port > 65535 {
			application.store.mu.Unlock()
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "网页管理端口范围必须是 1 至 65535"})
			return
		}
	}
	secretPath := strings.TrimSpace(payload.SecretPath)
	if secretPath == "" {
		secretPath = ui.SecretPath
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(secretPath) {
		application.store.mu.Unlock()
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "安全后缀仅能由英文字母和数字组成"})
		return
	}
	oldUsername, oldPassword, oldPort, oldPath := ui.Username, ui.Password, ui.Port, ui.SecretPath
	ui.Username, ui.Port, ui.SecretPath = username, port, secretPath
	if strings.TrimSpace(payload.Password) != "" {
		ui.Password = strings.TrimSpace(payload.Password)
	}
	reauthRequired := oldUsername != ui.Username || oldPassword != ui.Password
	restartNeeded := oldPort != ui.Port || oldPath != ui.SecretPath
	application.store.mu.Unlock()
	if err := application.store.saveUI(); err != nil {
		writeOperationResult(writer, "", err)
		return
	}
	if reauthRequired {
		application.sessionsMu.Lock()
		application.sessions = map[string]time.Time{}
		application.sessionsMu.Unlock()
	}
	message := "账号密码配置更新成功，已即时生效！"
	if restartNeeded {
		message = "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."
		application.scheduleRestart()
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "restart_needed": restartNeeded, "reauth_required": reauthRequired, "message": message})
}

func (application *webApplication) updateSettings(writer http.ResponseWriter, request *http.Request) {
	payload := map[string]any{}
	if err := decodeJSON(request, &payload); err != nil {
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	application.store.mu.Lock()
	ui := &application.store.ui
	oldPort, oldProxyPort := ui.Port, ui.ProxyPort
	if value, ok := payload["host"].(string); ok && strings.TrimSpace(value) != "" {
		ui.Host = strings.TrimSpace(value)
	}
	if value, ok := numberFromJSON(payload["port"]); ok && value > 0 && value <= 65535 {
		ui.Port = value
	}
	if raw, exists := payload["proxy_port"]; exists {
		value, ok := numberFromJSON(raw)
		if !ok || value < 1024 || value > 65535 {
			application.store.mu.Unlock()
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "代理出站端口范围必须是 1024 至 65535"})
			return
		}
		ui.ProxyPort = value
	}
	if ui.Port == ui.ProxyPort {
		application.store.mu.Unlock()
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "代理端口不能与网页端口相同"})
		return
	}
	if value, ok := payload["routing_mode"].(string); ok {
		valid := value == "auto" || value == "fixed_country" || value == "fixed_region" || value == "fixed_ip" || value == "favorites"
		if !valid {
			application.store.mu.Unlock()
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "无效的路由模式"})
			return
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
			application.store.mu.Unlock()
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "无效的IP出站类型过滤"})
			return
		}
		ui.RoutingIPType = value
	}
	if value, ok := payload["connection_enabled"].(bool); ok {
		ui.ConnectionEnabled = value
	}
	if value, ok := payload["fav_fail_fallback"].(bool); ok {
		ui.FavoriteFallback = value
	}
	if ui.RoutingMode == "fixed_region" && ui.ForceCountry == "" {
		application.store.mu.Unlock()
		writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "启用固定地区前，请先选择一个要锁定的国家"})
		return
	}
	if ui.RoutingMode == "fixed_ip" && ui.FixedNodeID == "" {
		ui.FixedNodeID = application.store.state.ActiveNodeID
		if ui.FixedNodeID == "" {
			application.store.mu.Unlock()
			writeJSONResponse(writer, http.StatusBadRequest, map[string]any{"ok": false, "error": "启用固定 IP 前，请先连接一个要锁定的节点"})
			return
		}
	}
	if ui.RoutingMode == "favorites" {
		ui.FavoriteFallback = false
	}
	restartNeeded := oldPort != ui.Port || oldProxyPort != ui.ProxyPort
	application.store.mu.Unlock()
	if err := application.store.saveUI(); err != nil {
		writeOperationResult(writer, "", err)
		return
	}
	application.enforceRoutingSettings()
	message := "配置更新成功，已即时生效！"
	if restartNeeded {
		message = "配置更新成功，代理出站端口变更，将在 2 秒内重启..."
		application.scheduleRestart()
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{"ok": true, "restart_needed": restartNeeded, "message": message})
}

func (application *webApplication) scheduleRestart() {
	if application.store.config.DisableBackground || envBool("AIMILIVPN_NO_AUTO_RESTART", false) {
		return
	}
	go func() {
		time.Sleep(2 * time.Second)
		application.store.logEvent("info", "System", "配置变更，进程退出以触发服务重启")
		os.Exit(0)
	}()
}

func (application *webApplication) enforceRoutingSettings() {
	ui, state, _ := application.store.snapshot()
	if state.ActiveNodeID == "" {
		return
	}
	candidate, found := application.store.nodeByID(state.ActiveNodeID)
	if !found || application.vpn.validateCandidate(candidate) != nil {
		application.store.logEvent("warning", "Routing", "当前活动节点不符合更新后的路由规则，已断开")
		application.vpn.stop("路由规则已更新，当前节点不再符合规则")
		if ui.ConnectionEnabled && ui.RoutingMode != "fixed_ip" {
			go application.autoSwitch(0)
		}
	}
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

func (application *webApplication) testProxy(writer http.ResponseWriter) {
	result := application.checkProxyHealth()
	application.updateProxyState(result)
	writeJSONResponse(writer, http.StatusOK, result)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func decodeJSON(request *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, 256<<10))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("请求 JSON 无效: %w", err)
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
