package vpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caichengle666/gatepilot/internal/store"
)

// Controller 管理 OpenVPN 进程的生命周期。
type Controller struct {
	mu            sync.Mutex
	application   *store.Store
	command       managedOpenVPNProcess
	nodeID        string
	testIndex     int
	versionOnce   sync.Once
	version       float64
	tunnels       map[string]*managedTunnel
	TunnelStopped func(TunnelStatus, bool)
}

const maxAdditionalTunnels = 8

// TunnelStatus 描述一条 Linux 附加 VPN 隧道及其独立代理入口。
type TunnelStatus struct {
	Device             string `json:"device"`
	NodeID             string `json:"node_id"`
	NodeIP             string `json:"node_ip"`
	ProxyPort          int    `json:"proxy_port"`
	PublishedProxyPort int    `json:"published_proxy_port"`
	Table              int    `json:"route_table"`
	Status             string `json:"status"`
	Message            string `json:"message"`
	StartedAt          int64  `json:"started_at"`
	HealthStatus       string `json:"health_status"`
	HealthMessage      string `json:"health_message"`
	HealthIP           string `json:"health_ip"`
	HealthLatencyMS    int64  `json:"health_latency_ms"`
	HealthFailures     int    `json:"health_failures"`
	LastHealthCheckAt  int64  `json:"last_health_check_at"`
}

type managedTunnel struct {
	TunnelStatus
	process          managedOpenVPNProcess
	done             <-chan error
	endpointHost     string
	endpointPriority int
}

type openVPNRun struct {
	process managedOpenVPNProcess
	done    <-chan error
	tail    []string
}

type openVPNFailure struct {
	code    string
	message string
	cause   error
}

func (failure *openVPNFailure) Error() string {
	return fmt.Sprintf("[%s] %s", failure.code, failure.message)
}

func (failure *openVPNFailure) Unwrap() error {
	return failure.cause
}

// NewController 创建 VPN 控制器。
func NewController(application *store.Store) *Controller {
	cleanupStaleVPNState(application.Config.OpenVPNCommand)
	return &Controller{application: application, testIndex: 10, tunnels: map[string]*managedTunnel{}}
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

func (c *Controller) commandFor(candidate store.Node, configPath, device, windowsDriver string, routeNopull bool) (*exec.Cmd, error) {
	parts, err := splitCommandLine(c.application.Config.OpenVPNCommand)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, errors.New("OPENVPN_CMD 不能为空")
	}
	executable, err := exec.LookPath(parts[0])
	if err != nil {
		return nil, c.openVPNError(err, nil)
	}
	authPath := filepath.Join(c.application.Config.DataDir, "vpngate_auth.txt")
	arguments := append(parts[1:],
		"--config", configPath,
		"--pull-filter", "ignore", "route-ipv6",
		"--pull-filter", "ignore", "ifconfig-ipv6",
		"--route-delay", "2", "--connect-retry-max", "1",
		"--connect-timeout", "15", "--auth-user-pass", authPath,
		"--auth-nocache", "--verb", "3",
	)
	arguments = append(arguments, openVPNDeviceArguments(device, c.openVPNVersion(), windowsDriver)...)
	arguments = append(arguments, openVPNRouteArguments(routeNopull)...)
	arguments = append(arguments, openVPNControlArguments(device)...)
	if c.openVPNVersion() >= 2.5 {
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
		proxyURL, proxyErr := store.ParseProxyURL(c.application.UpstreamProxy())
		if proxyErr != nil {
			return nil, proxyErr
		}
		if proxyURL != nil {
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
				if scheme != "socks" && scheme != "socks5" || socks5RequiresAuth(proxyURL.Hostname(), port) {
					authFile = filepath.Join(c.application.Config.DataDir, "upstream_proxy_auth.txt")
					if err := os.WriteFile(authFile, []byte(proxyURL.User.Username()+"\n"+password+"\n"), 0o600); err != nil {
						return nil, fmt.Errorf("写入上游代理认证文件失败: %w", err)
					}
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
	}
	return exec.Command(executable, arguments...), nil
}

func socks5RequiresAuth(host, port string) bool {
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		return true
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return true
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(connection, reply); err != nil {
		return true
	}
	return reply[0] == 0x05 && reply[1] == 0x02
}

func (c *Controller) openVPNVersion() float64 {
	c.versionOnce.Do(func() {
		c.version = 2.4
		parts, err := splitCommandLine(c.application.Config.OpenVPNCommand)
		if err != nil || len(parts) == 0 {
			return
		}
		executable, err := exec.LookPath(parts[0])
		if err != nil {
			return
		}
		output, err := exec.Command(executable, append(parts[1:], "--version")...).CombinedOutput()
		if err != nil {
			return
		}
		match := regexp.MustCompile(`OpenVPN\s+(\d+)\.(\d+)`).FindStringSubmatch(string(output))
		if len(match) != 3 {
			return
		}
		major, _ := strconv.Atoi(match[1])
		minor, _ := strconv.Atoi(match[2])
		c.version = float64(major) + float64(minor)/10
	})
	return c.version
}

// SplitCommandLine 将命令行字符串拆分为参数列表。
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
	characters := []rune(strings.TrimSpace(value))
	for index, character := range characters {
		if escaped {
			current.WriteRune(character)
			tokenStarted = true
			escaped = false
			continue
		}
		if character == '\\' && index+1 < len(characters) && (characters[index+1] == ' ' || characters[index+1] == '\t' || characters[index+1] == '\'' || characters[index+1] == '"') {
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
	if quote != 0 {
		return nil, errors.New("OPENVPN_CMD 存在未闭合的引号或转义符")
	}
	if escaped {
		current.WriteRune('\\')
	}
	flush()
	return parts, nil
}

func (c *Controller) prepareConfig(candidate store.Node, suffix string) (string, error) {
	if candidate.ConfigText == "" {
		return "", errors.New("节点没有 OpenVPN 配置")
	}
	path := filepath.Join(c.application.Config.DataDir, "configs", store.SafeName(candidate.ID)+suffix+".ovpn")
	if err := os.WriteFile(path, []byte(sanitizeOpenVPNConfig(candidate.ConfigText)), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (c *Controller) runUntilReady(ctx context.Context, candidate store.Node, device string, timeout time.Duration, routeNopull bool) (*openVPNRun, error) {
	drivers := openVPNDriverCandidates(c.openVPNVersion(), openVPNUsesBundledCore(c.application.Config.OpenVPNCommand))
	var lastError error
	for index, driver := range drivers {
		if driver == "tap-windows6" {
			message := "Wintun 不可用，正在安装或准备 TAP-Windows6 备用驱动"
			_ = c.application.SetState("connecting", message, "")
			_ = c.application.UpdateState(func(state *store.RuntimeState) { state.LastCheckMessage = message })
			c.application.LogEvent("warning", "OpenVPN", message)
			if tapErr := ensureTAPAdapter(c.application.Config.OpenVPNCommand); tapErr != nil {
				failure := &openVPNFailure{code: "ERR_VPN_DRIVER", message: "TAP 备用驱动准备失败: " + tapErr.Error(), cause: tapErr}
				_ = c.application.SetState("error", failure.Error(), "")
				_ = c.application.UpdateState(func(state *store.RuntimeState) { state.LastCheckMessage = failure.Error() })
				c.application.LogEvent("error", "OpenVPN", failure.Error())
				return nil, failure
			}
			message = "TAP-Windows6 备用驱动已准备完成，正在重新连接"
			_ = c.application.SetState("connecting", message, "")
			_ = c.application.UpdateState(func(state *store.RuntimeState) { state.LastCheckMessage = message })
			c.application.LogEvent("info", "OpenVPN", message)
		}
		run, err := c.runUntilReadyWithDriver(ctx, candidate, device, driver, timeout, routeNopull)
		if err == nil {
			return run, nil
		}
		lastError = err
		if index == len(drivers)-1 || !shouldRetryOpenVPNDriver(err) {
			break
		}
		c.application.LogEvent("warning", "OpenVPN", fmt.Sprintf("Windows 驱动 %s 不可用，尝试下一种驱动", driver))
	}
	return nil, lastError
}

func (c *Controller) runUntilReadyWithDriver(ctx context.Context, candidate store.Node, device, windowsDriver string, timeout time.Duration, routeNopull bool) (*openVPNRun, error) {
	ready := false
	defer func() {
		if !ready && !routeNopull {
			cleanupPolicyRouting()
		}
	}()
	configPath, err := c.prepareConfig(candidate, "_"+device)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(device, "tun_test") {
		defer os.Remove(configPath)
	}
	command, err := c.commandFor(candidate, configPath, device, windowsDriver, routeNopull)
	if err != nil {
		return nil, err
	}
	preparePolicyRouting()
	output, process, done, err := startOpenVPNProcess(command, windowsDriver)
	if err != nil {
		return nil, c.openVPNError(err, nil)
	}
	lines := make(chan string, 128)
	go func() {
		defer output.Close()
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			c.application.LogEvent("info", "OpenVPN", line)
			select {
			case lines <- line:
			default:
			}
		}
		close(lines)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	tail := make([]string, 0, 16)
	for {
		select {
		case line, open := <-lines:
			if !open {
				stopCommandAndWait(process, done)
				return nil, c.openVPNError(errors.New("OpenVPN 输出已关闭"), tail)
			}
			tail = append(tail, line)
			if len(tail) > 16 {
				tail = tail[len(tail)-16:]
			}
			if device == "tun0" || strings.HasPrefix(device, "tun_test") {
				c.updateHandshakeStatus(line)
			}
			lower := strings.ToLower(line)
			if strings.Contains(lower, "initialization sequence completed") {
				ready = true
				return &openVPNRun{process: process, done: done, tail: tail}, nil
			}
			if strings.Contains(lower, "auth_failed") || strings.Contains(lower, "fatal error") || strings.Contains(lower, "exiting due to fatal error") {
				stopCommandAndWait(process, done)
				return nil, c.openVPNError(errors.New(line), tail)
			}
		case waitErr := <-done:
			return nil, c.openVPNError(waitErr, tail)
		case <-ctx.Done():
			stopCommandAndWait(process, done)
			return nil, ctx.Err()
		case <-timer.C:
			stopCommandAndWait(process, done)
			return nil, c.openVPNError(errors.New("OpenVPN 连接超时"), tail)
		}
	}
}

func (c *Controller) updateHandshakeStatus(line string) {
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
	_ = c.application.UpdateState(func(state *store.RuntimeState) { state.LastCheckMessage = message })
}

func (c *Controller) openVPNError(cause error, tail []string) error {
	var failure *openVPNFailure
	if errors.As(cause, &failure) {
		return failure
	}
	output := strings.Join(tail, "\n")
	code, message := store.DiagnoseOpenVPNFailure(output, cause)
	if cause != nil && !strings.Contains(message, cause.Error()) {
		message += ": " + cause.Error()
	}
	return &openVPNFailure{code: code, message: message, cause: cause}
}

func shouldBlacklistOpenVPNFailure(err error) bool {
	var failure *openVPNFailure
	if !errors.As(err, &failure) {
		return false
	}
	switch failure.code {
	case "ERR_VPN_AUTH", "ERR_VPN_TLS", "ERR_VPN_REFUSED", "ERR_VPN_ROUTE", "ERR_VPN_TIMEOUT":
		return true
	default:
		return false
	}
}

// Connect 连接到指定节点。
func (c *Controller) Connect(nodeID string) (string, error) {
	return c.ConnectContext(context.Background(), nodeID)
}

// ConnectContext 连接到指定节点，并允许后台自动连接被手动操作取消。
func (c *Controller) ConnectContext(ctx context.Context, nodeID string) (string, error) {
	candidate, found := c.application.NodeByID(nodeID)
	if !found {
		return "", fmt.Errorf("找不到节点 %s", nodeID)
	}
	if err := c.ValidateCandidate(candidate); err != nil {
		return "", err
	}
	c.application.EnableConnectionFor(candidate)
	_ = c.application.SaveUI()
	c.Stop("切换 VPN 节点")
	_ = c.application.SetState("connecting", "正在启动 OpenVPN", "")
	_ = c.application.UpdateState(func(state *store.RuntimeState) {
		state.LastCheckMessage = "正在连接节点 " + candidate.ID
		state.ActiveNodeLatency = "测试中..."
	})
	run, err := c.runUntilReady(ctx, candidate, "tun0", c.application.Config.OpenVPNTimeout, false)
	if err != nil {
		if shouldBlacklistOpenVPNFailure(err) {
			c.application.MarkBlacklisted(candidate, err.Error())
		}
		c.application.UpdateNodeProbe(candidate.ID, false, 0, err.Error())
		_ = c.application.SetState("error", err.Error(), "")
		return "", err
	}
	ui, _, _ := c.application.Snapshot()
	if !ui.ConnectionEnabled {
		stopCommandAndWait(run.process, run.done)
		cleanupPolicyRouting()
		_ = c.application.SetState("disconnected", "用户已断开连接", "")
		return "", context.Canceled
	}
	c.mu.Lock()
	c.command, c.nodeID = run.process, candidate.ID
	c.mu.Unlock()
	setupPolicyRouting("tun0")
	if err := waitForVPNReady(15 * time.Second); err != nil {
		c.Stop("VPN 网卡未就绪")
		c.application.UpdateNodeProbe(candidate.ID, false, 0, err.Error())
		_ = c.application.SetState("error", err.Error(), "")
		return "", err
	}
	latency := MeasureNodeLatency(candidate, 5*time.Second)
	c.application.UpdateNodeProbe(candidate.ID, true, latency, "OpenVPN 握手成功")
	_ = c.application.SetState("connected", "OpenVPN 已连接", candidate.ID)
	_ = c.application.UpdateState(func(state *store.RuntimeState) {
		state.LastCheckAt = time.Now().Unix()
		state.LastCheckMessage = "Connected " + candidate.ID
		if latency > 0 {
			state.ActiveNodeLatency = fmt.Sprintf("%d ms", latency)
		} else {
			state.ActiveNodeLatency = "检测超时"
		}
	})
	c.application.LogEvent("info", "VPN", "节点 "+candidate.ID+" 连接成功，tun0 已启用")
	go c.monitor(run.process, candidate, run.done)
	return "已连接 " + candidate.ID, nil
}

// ValidateCandidate 检查节点是否符合当前路由规则。
func (c *Controller) ValidateCandidate(candidate store.Node) error {
	ui, _, _ := c.application.Snapshot()
	switch ui.RoutingMode {
	case "fixed_country", "fixed_region":
		if ui.ForceCountry != "" && !store.CountryMatches(candidate, ui.ForceCountry) {
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

// TestNode 测试单个节点的连通性。
func (c *Controller) TestNode(nodeID string) (store.Node, error) {
	return c.TestNodeContext(context.Background(), nodeID)
}

// TestNodeContext 测试单个节点，并允许后台维护被手动连接取消。
func (c *Controller) TestNodeContext(ctx context.Context, nodeID string) (store.Node, error) {
	candidate, found := c.application.NodeByID(nodeID)
	if !found {
		return store.Node{}, fmt.Errorf("找不到节点 %s", nodeID)
	}
	c.application.UpdateNodeProbe(candidate.ID, false, 0, "正在检测节点连通性...")
	c.mu.Lock()
	c.testIndex++
	if c.testIndex > 99 {
		c.testIndex = 10
	}
	device := fmt.Sprintf("tun_test%d", c.testIndex)
	c.mu.Unlock()
	started := time.Now()
	run, err := c.runUntilReady(ctx, candidate, device, minDuration(c.application.Config.OpenVPNTimeout, 12*time.Second), true)
	if errors.Is(err, context.Canceled) {
		c.application.UpdateNodeProbe(candidate.ID, false, 0, "后台检测已取消")
		updated, _ := c.application.NodeByID(candidate.ID)
		return updated, err
	}
	latency := MeasureNodeLatency(candidate, 5*time.Second)
	if err != nil {
		c.application.UpdateNodeProbe(candidate.ID, false, latency, err.Error())
		if shouldBlacklistOpenVPNFailure(err) {
			c.application.MarkBlacklisted(candidate, err.Error())
		}
		updated, _ := c.application.NodeByID(candidate.ID)
		return updated, err
	}
	stopCommand(run.process)
	select {
	case <-run.done:
	case <-time.After(3 * time.Second):
	}
	if latency <= 0 {
		latency = time.Since(started).Milliseconds()
	}
	c.application.UpdateNodeProbe(candidate.ID, true, latency, "OpenVPN 握手成功")
	updated, _ := c.application.NodeByID(candidate.ID)
	return updated, nil
}

// TestNodes 批量测试节点。
func (c *Controller) TestNodes(ids []string) []store.Node {
	return c.TestNodesContext(context.Background(), ids)
}

// TestNodesContext 批量测试节点，并在上下文取消后停止未开始和正在进行的测试。
func (c *Controller) TestNodesContext(ctx context.Context, ids []string) []store.Node {
	limit := c.application.Config.ManualTestNodeLimit
	if len(ids) > limit {
		ids = ids[:limit]
	}
	results := make([]store.Node, len(ids))
	workerCount := NodeTestWorkerCount(len(ids))
	semaphore := make(chan struct{}, workerCount)
	var waitGroup sync.WaitGroup
	for index, id := range ids {
		waitGroup.Add(1)
		go func(index int, id string) {
			defer waitGroup.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()
			results[index], _ = c.TestNodeContext(ctx, id)
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

// NodeTestWorkerCount 根据平台和节点数决定并发数。
func NodeTestWorkerCount(total int) int {
	if runtime.GOOS == "windows" && total > 1 {
		return 1
	}
	if total > 5 {
		return 5
	}
	return total
}

// MeasureNodeLatency 通过 TCP 连接测量节点延迟。
func MeasureNodeLatency(candidate store.Node, timeout time.Duration) int64 {
	host := store.FirstNonEmpty(candidate.RemoteHost, candidate.IP)
	if host == "" || candidate.RemotePort == 0 {
		return candidate.Ping
	}
	started := time.Now()
	connection, err := store.NetDialTimeout("tcp", host, candidate.RemotePort, timeout)
	if err != nil {
		return candidate.Ping
	}
	_ = connection.Close()
	return time.Since(started).Milliseconds()
}

func (c *Controller) monitor(command managedOpenVPNProcess, candidate store.Node, done <-chan error) {
	err := <-done
	c.mu.Lock()
	if c.command != command {
		c.mu.Unlock()
		return
	}
	c.command, c.nodeID = nil, ""
	c.mu.Unlock()
	cleanupPolicyRouting()
	message := "OpenVPN 进程已退出"
	if err != nil {
		message = "OpenVPN 进程异常退出: " + err.Error()
	}
	_, state, _ := c.application.Snapshot()
	if state.ActiveNodeID == candidate.ID {
		c.application.UpdateNodeProbe(candidate.ID, false, 0, message)
		_ = c.application.SetState("disconnected", message, "")
		_ = c.application.UpdateState(func(state *store.RuntimeState) { state.ActiveNodeLatency = "无活动连接" })
	}
}

// Stop 停止当前 VPN 连接。
func (c *Controller) Stop(message string) {
	c.mu.Lock()
	command := c.command
	c.command, c.nodeID = nil, ""
	c.mu.Unlock()
	if command != nil {
		stopCommand(command)
	}
	cleanupPolicyRouting()
	_ = c.application.SetState("disconnected", message, "")
	_ = c.application.UpdateState(func(state *store.RuntimeState) { state.ActiveNodeLatency = "无活动连接" })
}

func stopCommand(command managedOpenVPNProcess) {
	if command == nil {
		return
	}
	command.Stop()
}

func stopCommandAndWait(command managedOpenVPNProcess, done <-chan error) {
	stopCommand(command)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

// Running 返回 VPN 是否正在运行。
func (c *Controller) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.command != nil
}

// ConnectTunnel 在 Linux 上启动一条附加隧道，不影响主 tun0 连接。
func (c *Controller) ConnectTunnel(ctx context.Context, nodeID string, proxyPort int) (TunnelStatus, error) {
	return c.connectTunnel(ctx, nodeID, proxyPort, "")
}

// ConnectTunnelOnDevice 在指定的附加 TUN 槽位建立隧道，供固定端口故障切换使用。
func (c *Controller) ConnectTunnelOnDevice(ctx context.Context, nodeID string, proxyPort int, device string) (TunnelStatus, error) {
	return c.connectTunnel(ctx, nodeID, proxyPort, device)
}

func (c *Controller) connectTunnel(ctx context.Context, nodeID string, proxyPort int, requestedDevice string) (TunnelStatus, error) {
	if runtime.GOOS != "linux" {
		return TunnelStatus{}, errors.New("附加 VPN 隧道目前仅支持 Linux")
	}
	candidate, found := c.application.NodeByID(nodeID)
	if !found {
		return TunnelStatus{}, fmt.Errorf("找不到节点 %s", nodeID)
	}
	if err := c.ValidateCandidate(candidate); err != nil {
		return TunnelStatus{}, err
	}
	c.mu.Lock()
	if len(c.tunnels) >= maxAdditionalTunnels {
		c.mu.Unlock()
		return TunnelStatus{}, fmt.Errorf("附加隧道最多同时运行 %d 条", maxAdditionalTunnels)
	}
	for _, tunnel := range c.tunnels {
		if tunnel.ProxyPort == proxyPort {
			c.mu.Unlock()
			return TunnelStatus{}, fmt.Errorf("代理端口 %d 已被附加隧道使用", proxyPort)
		}
	}
	index := 0
	if requestedDevice != "" {
		parsed, err := strconv.Atoi(strings.TrimPrefix(requestedDevice, "tun"))
		if err != nil || parsed < 1 || parsed > maxAdditionalTunnels || !strings.HasPrefix(requestedDevice, "tun") {
			c.mu.Unlock()
			return TunnelStatus{}, fmt.Errorf("附加隧道设备名无效: %s", requestedDevice)
		}
		if _, exists := c.tunnels[requestedDevice]; exists {
			c.mu.Unlock()
			return TunnelStatus{}, fmt.Errorf("附加隧道设备 %s 已被使用", requestedDevice)
		}
		index = parsed
	} else {
		for candidateIndex := 1; candidateIndex <= maxAdditionalTunnels; candidateIndex++ {
			device := fmt.Sprintf("tun%d", candidateIndex)
			if _, exists := c.tunnels[device]; !exists {
				index = candidateIndex
				break
			}
		}
	}
	device := fmt.Sprintf("tun%d", index)
	tunnel := &managedTunnel{TunnelStatus: TunnelStatus{
		Device: device, NodeID: nodeID, NodeIP: store.FirstNonEmpty(candidate.IP, candidate.RemoteHost), ProxyPort: proxyPort,
		PublishedProxyPort: c.application.Config.TunnelProxyPublishedPortStart + index - 1, Table: 100 + index,
		Status: "connecting", Message: "正在建立附加隧道", HealthStatus: "checking", StartedAt: time.Now().Unix(),
	}}
	tunnel.endpointHost = store.FirstNonEmpty(candidate.RemoteHost, candidate.IP)
	tunnel.endpointPriority = 100 + index
	c.tunnels[device] = tunnel
	c.mu.Unlock()

	endpointRouteReady := setupEndpointMainRoute(tunnel.endpointHost, tunnel.endpointPriority)
	run, err := c.runUntilReady(ctx, candidate, device, c.application.Config.OpenVPNTimeout, true)
	if err != nil {
		if endpointRouteReady {
			cleanupEndpointMainRoute(tunnel.endpointHost, tunnel.endpointPriority)
		}
		c.removeTunnel(device, nil)
		return TunnelStatus{}, err
	}
	setupDevicePolicyRouting(device, tunnel.Table)
	if err := waitForDeviceReady(device, 15*time.Second); err != nil {
		stopCommandAndWait(run.process, run.done)
		cleanupDevicePolicyRouting(device, tunnel.Table)
		if endpointRouteReady {
			cleanupEndpointMainRoute(tunnel.endpointHost, tunnel.endpointPriority)
		}
		c.removeTunnel(device, nil)
		return TunnelStatus{}, err
	}
	c.mu.Lock()
	current := c.tunnels[device]
	if current != tunnel {
		c.mu.Unlock()
		stopCommandAndWait(run.process, run.done)
		cleanupDevicePolicyRouting(device, tunnel.Table)
		if endpointRouteReady {
			cleanupEndpointMainRoute(tunnel.endpointHost, tunnel.endpointPriority)
		}
		return TunnelStatus{}, errors.New("附加隧道启动已取消")
	}
	tunnel.process = run.process
	tunnel.done = run.done
	tunnel.Status = "connected"
	tunnel.Message = "OpenVPN 已连接"
	status := tunnel.TunnelStatus
	c.mu.Unlock()
	c.application.LogEvent("info", "VPN", fmt.Sprintf("附加隧道 %s 已连接节点 %s，代理端口 %d", device, nodeID, proxyPort))
	go c.monitorTunnel(device, run.process, run.done)
	return status, nil
}

func (c *Controller) monitorTunnel(device string, process managedOpenVPNProcess, done <-chan error) {
	err := <-done
	c.mu.Lock()
	tunnel := c.tunnels[device]
	if tunnel == nil || tunnel.process != process {
		c.mu.Unlock()
		return
	}
	delete(c.tunnels, device)
	c.mu.Unlock()
	cleanupDevicePolicyRouting(device, tunnel.Table)
	cleanupEndpointMainRoute(tunnel.endpointHost, tunnel.endpointPriority)
	if candidate, found := c.application.NodeByID(tunnel.NodeID); found {
		c.application.MarkBlacklisted(candidate, "附加隧道异常退出")
	}
	message := "OpenVPN 进程已退出"
	if err != nil {
		message = "OpenVPN 进程异常退出: " + err.Error()
	}
	c.application.LogEvent("warning", "VPN", fmt.Sprintf("附加隧道 %s 已断开: %s", device, message))
	if c.TunnelStopped != nil {
		c.TunnelStopped(tunnel.TunnelStatus, true)
	}
}

func (c *Controller) removeTunnel(device string, process managedOpenVPNProcess) *managedTunnel {
	c.mu.Lock()
	defer c.mu.Unlock()
	tunnel := c.tunnels[device]
	if tunnel != nil && (process == nil || tunnel.process == process) {
		delete(c.tunnels, device)
		return tunnel
	}
	return nil
}

// DisconnectTunnel 停止指定附加隧道。
func (c *Controller) DisconnectTunnel(device string) error {
	tunnel := c.removeTunnel(device, nil)
	if tunnel == nil {
		return fmt.Errorf("找不到附加隧道 %s", device)
	}
	if tunnel.process != nil {
		stopCommand(tunnel.process)
	}
	cleanupDevicePolicyRouting(device, tunnel.Table)
	cleanupEndpointMainRoute(tunnel.endpointHost, tunnel.endpointPriority)
	c.application.LogEvent("info", "VPN", "附加隧道 "+device+" 已断开")
	if c.TunnelStopped != nil {
		c.TunnelStopped(tunnel.TunnelStatus, false)
	}
	return nil
}

// UpdateTunnelHealth 更新附加隧道的代理出口健康状态。
func (c *Controller) UpdateTunnelHealth(device string, healthy bool, ip, message string, latencyMS int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tunnel := c.tunnels[device]
	if tunnel == nil {
		return
	}
	tunnel.LastHealthCheckAt = time.Now().Unix()
	tunnel.HealthIP = ip
	tunnel.HealthMessage = message
	tunnel.HealthLatencyMS = latencyMS
	if healthy {
		tunnel.HealthStatus = "healthy"
		tunnel.HealthFailures = 0
	} else {
		tunnel.HealthStatus = "unhealthy"
		tunnel.HealthFailures++
	}
}

// Tunnels 返回附加隧道状态快照。
func (c *Controller) Tunnels() []TunnelStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]TunnelStatus, 0, len(c.tunnels))
	for _, tunnel := range c.tunnels {
		result = append(result, tunnel.TunnelStatus)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Device < result[right].Device })
	return result
}

// StopAll 停止主隧道和全部附加隧道。
func (c *Controller) StopAll(message string) {
	c.Stop(message)
	for _, tunnel := range c.Tunnels() {
		_ = c.DisconnectTunnel(tunnel.Device)
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
