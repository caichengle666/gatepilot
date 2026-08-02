package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type vpnController struct {
	mu          sync.Mutex
	application *store
	command     *exec.Cmd
	nodeID      string
	testIndex   int
	versionOnce sync.Once
	version     float64
}

type openVPNRun struct {
	command *exec.Cmd
	done    <-chan error
	tail    []string
}

func newVPNController(application *store) *vpnController {
	return &vpnController{application: application, testIndex: 10}
}

func sanitizeOpenVPNConfig(raw string) string {
	blocked := map[string]bool{
		"up": true, "down": true, "route-up": true, "ipchange": true,
		"client-connect": true, "client-disconnect": true, "learn-address": true,
		"plugin": true, "script-security": true, "tls-verify": true,
		"auth-user-pass": true, "management": true, "management-client-auth": true,
	}
	lines := make([]string, 0, strings.Count(raw, "\n")+1)
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) > 0 && blocked[strings.ToLower(fields[0])] {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (controller *vpnController) commandFor(candidate node, configPath, device string, routeNopull bool) (*exec.Cmd, error) {
	parts, err := splitCommandLine(controller.application.config.OpenVPNCommand)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, errors.New("OPENVPN_CMD 不能为空")
	}
	authPath := filepath.Join(controller.application.config.DataDir, "vpngate_auth.txt")
	arguments := append(parts[1:],
		"--config", configPath,
		"--pull-filter", "ignore", "route-ipv6",
		"--pull-filter", "ignore", "ifconfig-ipv6",
		"--route-delay", "2", "--connect-retry-max", "1",
		"--connect-timeout", "15", "--auth-user-pass", authPath,
		"--auth-nocache", "--verb", "3",
	)
	arguments = append(arguments, openVPNDeviceArguments(device, controller.openVPNVersion())...)
	if routeNopull {
		arguments = append(arguments, "--route-nopull")
	}
	if controller.openVPNVersion() >= 2.5 {
		arguments = append(arguments,
			"--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-128-CBC",
			"--data-ciphers-fallback", "AES-128-CBC",
		)
	} else {
		arguments = append(arguments, "--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305")
	}
	if info, err := os.Stat("/etc/ssl/certs"); err == nil && info.IsDir() {
		arguments = append(arguments, "--capath", "/etc/ssl/certs")
	}
	if strings.HasPrefix(strings.ToLower(candidate.Protocol), "tcp") {
		proxyURL, proxyErr := parseProxyURL(getenv("UPSTREAM_PROXY"))
		if proxyErr != nil {
			return nil, proxyErr
		}
		if proxyURL == nil {
			return exec.Command(parts[0], arguments...), nil
		}
		scheme := strings.ToLower(proxyURL.Scheme)
		port := proxyURL.Port()
		if port == "" {
			if scheme == "socks" || scheme == "socks5" {
				port = "1080"
			} else {
				port = "8080"
			}
		}
		authFile := ""
		if proxyURL.User != nil {
			password, _ := proxyURL.User.Password()
			authFile = filepath.Join(controller.application.config.DataDir, "upstream_proxy_auth.txt")
			if err := os.WriteFile(authFile, []byte(proxyURL.User.Username()+"\n"+password+"\n"), 0o600); err != nil {
				return nil, fmt.Errorf("写入上游代理认证文件失败: %w", err)
			}
		}
		switch scheme {
		case "socks", "socks5":
			arguments = append(arguments, "--socks-proxy", proxyURL.Hostname(), port)
			if authFile != "" {
				arguments = append(arguments, authFile)
			}
		case "http", "https":
			arguments = append(arguments, "--http-proxy", proxyURL.Hostname(), port)
			if authFile != "" {
				arguments = append(arguments, authFile)
			}
		default:
			return nil, fmt.Errorf("OpenVPN 不支持上游代理协议 %q", scheme)
		}
	}
	return exec.Command(parts[0], arguments...), nil
}

func (controller *vpnController) openVPNVersion() float64 {
	controller.versionOnce.Do(func() {
		controller.version = 2.4
		parts, err := splitCommandLine(controller.application.config.OpenVPNCommand)
		if err != nil || len(parts) == 0 {
			return
		}
		output, err := exec.Command(parts[0], append(parts[1:], "--version")...).CombinedOutput()
		if err != nil {
			return
		}
		match := regexp.MustCompile(`OpenVPN\s+(\d+)\.(\d+)`).FindStringSubmatch(string(output))
		if len(match) != 3 {
			return
		}
		major, _ := strconv.Atoi(match[1])
		minor, _ := strconv.Atoi(match[2])
		controller.version = float64(major) + float64(minor)/10
	})
	return controller.version
}

func splitCommandLine(value string) ([]string, error) {
	parts := []string{}
	var current strings.Builder
	var quote rune
	escaped := false
	tokenStarted := false
	flush := func() {
		if tokenStarted {
			parts = append(parts, current.String())
			current.Reset()
			tokenStarted = false
		}
	}
	for _, character := range strings.TrimSpace(value) {
		if escaped {
			current.WriteRune(character)
			tokenStarted = true
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			tokenStarted = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			tokenStarted = true
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			tokenStarted = true
			continue
		}
		if character == ' ' || character == '\t' || character == '\n' {
			flush()
			continue
		}
		current.WriteRune(character)
		tokenStarted = true
	}
	if quote != 0 || escaped {
		return nil, errors.New("OPENVPN_CMD 存在未闭合的引号或转义符")
	}
	flush()
	return parts, nil
}

func (controller *vpnController) prepareConfig(candidate node, suffix string) (string, error) {
	if candidate.ConfigText == "" {
		return "", errors.New("节点没有 OpenVPN 配置")
	}
	path := filepath.Join(controller.application.config.DataDir, "configs", safeName(candidate.ID)+suffix+".ovpn")
	if err := os.WriteFile(path, []byte(sanitizeOpenVPNConfig(candidate.ConfigText)), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (controller *vpnController) runUntilReady(candidate node, device string, timeout time.Duration) (*openVPNRun, error) {
	configPath, err := controller.prepareConfig(candidate, "_"+device)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(device, "tun_test") {
		defer os.Remove(configPath)
	}
	command, err := controller.commandFor(candidate, configPath, device, true)
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = command.Stdout
	preparePolicyRouting()
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("OpenVPN 启动失败: %w", err)
	}
	lines := make(chan string, 128)
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			controller.application.logEvent("info", "OpenVPN", line)
			select {
			case lines <- line:
			default:
			}
		}
		close(lines)
	}()
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	tail := make([]string, 0, 16)
	for {
		select {
		case line, open := <-lines:
			if !open {
				stopCommand(command)
				return nil, controller.openVPNError(errors.New("OpenVPN 输出已关闭"), tail)
			}
			tail = append(tail, line)
			if len(tail) > 16 {
				tail = tail[len(tail)-16:]
			}
			controller.updateHandshakeStatus(line)
			lower := strings.ToLower(line)
			if strings.Contains(lower, "initialization sequence completed") {
				return &openVPNRun{command: command, done: done, tail: tail}, nil
			}
			if strings.Contains(lower, "auth_failed") || strings.Contains(lower, "fatal error") || strings.Contains(lower, "exiting due to fatal error") {
				stopCommand(command)
				return nil, controller.openVPNError(errors.New(line), tail)
			}
		case waitErr := <-done:
			return nil, controller.openVPNError(waitErr, tail)
		case <-timer.C:
			stopCommand(command)
			return nil, controller.openVPNError(errors.New("OpenVPN 连接超时"), tail)
		}
	}
}

func (controller *vpnController) updateHandshakeStatus(line string) {
	lower := strings.ToLower(line)
	message := "正在启动 OpenVPN"
	switch {
	case strings.Contains(lower, "udp link remote") || strings.Contains(lower, "tcp connection established"):
		message = "已连接节点端口，正在进行 TLS 握手"
	case strings.Contains(lower, "peer connection initiated"):
		message = "TLS 握手成功，正在获取隧道参数"
	case strings.Contains(lower, "tun/tap device"):
		message = "隧道设备已创建，正在配置网络"
	default:
		return
	}
	_ = controller.application.updateState(func(state *runtimeState) { state.LastCheckMessage = message })
}

func (controller *vpnController) openVPNError(cause error, tail []string) error {
	output := strings.Join(tail, "\n")
	code, message := diagnoseOpenVPNFailure(output, cause)
	if cause != nil && !strings.Contains(message, cause.Error()) {
		message += ": " + cause.Error()
	}
	return fmt.Errorf("[%s] %s", code, message)
}

func (controller *vpnController) connect(nodeID string) (string, error) {
	candidate, found := controller.application.nodeByID(nodeID)
	if !found {
		return "", fmt.Errorf("找不到节点 %s", nodeID)
	}
	if err := controller.validateCandidate(candidate); err != nil {
		return "", err
	}
	controller.application.mu.Lock()
	controller.application.ui.ConnectionEnabled = true
	if controller.application.ui.RoutingMode == "fixed_ip" {
		controller.application.ui.FixedNodeID = candidate.ID
	}
	controller.application.mu.Unlock()
	_ = controller.application.saveUI()
	controller.stop("切换 VPN 节点")
	_ = controller.application.setState("connecting", "正在启动 OpenVPN", "")
	_ = controller.application.updateState(func(state *runtimeState) {
		state.LastCheckMessage = "正在连接节点 " + candidate.ID
		state.ActiveNodeLatency = "测试中..."
	})
	run, err := controller.runUntilReady(candidate, "tun0", controller.application.config.OpenVPNTimeout)
	if err != nil {
		controller.application.markBlacklisted(candidate, err.Error())
		controller.updateNodeProbe(candidate.ID, false, 0, err.Error())
		_ = controller.application.setState("error", err.Error(), "")
		return "", err
	}
	controller.mu.Lock()
	controller.command, controller.nodeID = run.command, candidate.ID
	controller.mu.Unlock()
	setupPolicyRouting("tun0")
	latency := measureNodeLatency(candidate, 5*time.Second)
	controller.updateNodeProbe(candidate.ID, true, latency, "OpenVPN 握手成功")
	_ = controller.application.setState("connected", "OpenVPN 已连接", candidate.ID)
	_ = controller.application.updateState(func(state *runtimeState) {
		state.LastCheckAt = time.Now().Unix()
		state.LastCheckMessage = "Connected " + candidate.ID
		if latency > 0 {
			state.ActiveNodeLatency = fmt.Sprintf("%d ms", latency)
		} else {
			state.ActiveNodeLatency = "检测超时"
		}
	})
	controller.application.logEvent("info", "VPN", "节点 "+candidate.ID+" 连接成功，tun0 已启用")
	go controller.monitor(run.command, candidate, run.done)
	return "已连接 " + candidate.ID, nil
}

func (controller *vpnController) validateCandidate(candidate node) error {
	ui, _, _ := controller.application.snapshot()
	switch ui.RoutingMode {
	case "fixed_country", "fixed_region":
		if ui.ForceCountry != "" && !countryMatches(candidate, ui.ForceCountry) {
			return fmt.Errorf("当前已锁定国家【%s】，不能连接其他国家节点", ui.ForceCountry)
		}
	case "favorites":
		allowed := false
		for _, id := range ui.FavoriteNodeIDs {
			allowed = allowed || id == candidate.ID
		}
		if !allowed {
			return errors.New("当前处于仅用收藏模式，不能连接未收藏节点")
		}
	}
	if ui.RoutingIPType == "residential" && candidate.IPType != "residential" && candidate.IPType != "mobile" {
		return errors.New("当前已锁定住宅 IP 出站，不能连接非住宅节点")
	}
	if ui.RoutingIPType == "hosting" && candidate.IPType != "hosting" {
		return errors.New("当前已锁定机房 IP 出站，不能连接非机房节点")
	}
	return nil
}

func (controller *vpnController) testNode(nodeID string) (node, error) {
	candidate, found := controller.application.nodeByID(nodeID)
	if !found {
		return node{}, fmt.Errorf("找不到节点 %s", nodeID)
	}
	controller.updateNodeProbe(candidate.ID, false, 0, "正在检测节点连通性...")
	controller.mu.Lock()
	controller.testIndex++
	if controller.testIndex > 99 {
		controller.testIndex = 10
	}
	device := fmt.Sprintf("tun_test%d", controller.testIndex)
	controller.mu.Unlock()
	started := time.Now()
	run, err := controller.runUntilReady(candidate, device, minDuration(controller.application.config.OpenVPNTimeout, 12*time.Second))
	latency := measureNodeLatency(candidate, 5*time.Second)
	if err != nil {
		controller.updateNodeProbe(candidate.ID, false, latency, err.Error())
		controller.application.markBlacklisted(candidate, err.Error())
		updated, _ := controller.application.nodeByID(candidate.ID)
		return updated, err
	}
	stopCommand(run.command)
	select {
	case <-run.done:
	case <-time.After(3 * time.Second):
	}
	if latency <= 0 {
		latency = time.Since(started).Milliseconds()
	}
	controller.updateNodeProbe(candidate.ID, true, latency, "OpenVPN 握手成功")
	updated, _ := controller.application.nodeByID(candidate.ID)
	return updated, nil
}

func (controller *vpnController) testNodes(ids []string) []node {
	limit := controller.application.config.ManualTestNodeLimit
	if len(ids) > limit {
		ids = ids[:limit]
	}
	results := make([]node, len(ids))
	workerCount := len(ids)
	if workerCount > 5 {
		workerCount = 5
	}
	semaphore := make(chan struct{}, workerCount)
	var waitGroup sync.WaitGroup
	for index, id := range ids {
		waitGroup.Add(1)
		go func(index int, id string) {
			defer waitGroup.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results[index], _ = controller.testNode(id)
		}(index, id)
	}
	waitGroup.Wait()
	completed := results[:0]
	for _, result := range results {
		if result.ID != "" {
			completed = append(completed, result)
		}
	}
	return completed
}

func (controller *vpnController) updateNodeProbe(id string, available bool, latency int64, message string) {
	controller.application.mu.Lock()
	for index := range controller.application.nodes {
		if controller.application.nodes[index].ID != id {
			continue
		}
		if message == "正在检测节点连通性..." {
			controller.application.nodes[index].ProbeStatus = "testing"
		} else if available {
			controller.application.nodes[index].ProbeStatus = "available"
		} else {
			controller.application.nodes[index].ProbeStatus = "unavailable"
		}
		controller.application.nodes[index].ProbeMessage = message
		controller.application.nodes[index].ProbedAt = time.Now().Unix()
		controller.application.nodes[index].LatencyMS = latency
	}
	controller.application.nodes = sortNodes(controller.application.nodes)
	controller.application.mu.Unlock()
	_ = controller.application.saveNodes()
}

func measureNodeLatency(candidate node, timeout time.Duration) int64 {
	host := firstNonEmpty(candidate.RemoteHost, candidate.IP)
	if host == "" || candidate.RemotePort == 0 {
		return candidate.Ping
	}
	started := time.Now()
	connection, err := netDialTimeout("tcp", host, candidate.RemotePort, timeout)
	if err != nil {
		return candidate.Ping
	}
	_ = connection.Close()
	return time.Since(started).Milliseconds()
}

func (controller *vpnController) monitor(command *exec.Cmd, candidate node, done <-chan error) {
	err := <-done
	controller.mu.Lock()
	if controller.command != command {
		controller.mu.Unlock()
		return
	}
	controller.command, controller.nodeID = nil, ""
	controller.mu.Unlock()
	cleanupPolicyRouting()
	message := "OpenVPN 进程已退出"
	if err != nil {
		message = "OpenVPN 进程异常退出: " + err.Error()
	}
	_, state, _ := controller.application.snapshot()
	if state.ActiveNodeID == candidate.ID {
		controller.application.markBlacklisted(candidate, message)
		_ = controller.application.setState("disconnected", message, "")
		_ = controller.application.updateState(func(state *runtimeState) { state.ActiveNodeLatency = "无活动连接" })
	}
}

func (controller *vpnController) stop(message string) {
	controller.mu.Lock()
	command := controller.command
	controller.command, controller.nodeID = nil, ""
	controller.mu.Unlock()
	if command != nil {
		stopCommand(command)
	}
	cleanupPolicyRouting()
	_ = controller.application.setState("disconnected", message, "")
	_ = controller.application.updateState(func(state *runtimeState) { state.ActiveNodeLatency = "无活动连接" })
}

func stopCommand(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Signal(os.Interrupt)
	time.Sleep(250 * time.Millisecond)
	_ = command.Process.Kill()
}

func (controller *vpnController) running() bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.command != nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
