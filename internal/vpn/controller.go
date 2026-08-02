package vpn

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caichengle666/gatepilot/internal/store"
)

// Controller 管理 OpenVPN 进程的生命周期。
type Controller struct {
	mu          sync.Mutex
	application *store.Store
	command     managedOpenVPNProcess
	nodeID      string
	testIndex   int
	versionOnce sync.Once
	version     float64
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
	return &Controller{application: application, testIndex: 10}
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

func (c *Controller) runUntilReady(candidate store.Node, device string, timeout time.Duration, routeNopull bool) (*openVPNRun, error) {
	drivers := openVPNDriverCandidates(c.openVPNVersion())
	var lastError error
	for index, driver := range drivers {
		if driver == "tap-windows6" {
			if tapErr := ensureTAPAdapter(c.application.Config.OpenVPNCommand); tapErr != nil {
				c.application.LogEvent("warning", "OpenVPN", "自动创建 TAP 网卡失败: "+tapErr.Error())
			}
		}
		run, err := c.runUntilReadyWithDriver(candidate, device, driver, timeout, routeNopull)
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

func (c *Controller) runUntilReadyWithDriver(candidate store.Node, device, windowsDriver string, timeout time.Duration, routeNopull bool) (*openVPNRun, error) {
	ready := false
	defer func() {
		if !ready {
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
			c.updateHandshakeStatus(line)
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
	run, err := c.runUntilReady(candidate, "tun0", c.application.Config.OpenVPNTimeout, false)
	if err != nil {
		if shouldBlacklistOpenVPNFailure(err) {
			c.application.MarkBlacklisted(candidate, err.Error())
		}
		c.application.UpdateNodeProbe(candidate.ID, false, 0, err.Error())
		_ = c.application.SetState("error", err.Error(), "")
		return "", err
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
	run, err := c.runUntilReady(candidate, device, minDuration(c.application.Config.OpenVPNTimeout, 12*time.Second), true)
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
	cleanupPolicyRouting()
	if latency <= 0 {
		latency = time.Since(started).Milliseconds()
	}
	c.application.UpdateNodeProbe(candidate.ID, true, latency, "OpenVPN 握手成功")
	updated, _ := c.application.NodeByID(candidate.ID)
	return updated, nil
}

// TestNodes 批量测试节点。
func (c *Controller) TestNodes(ids []string) []store.Node {
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
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results[index], _ = c.TestNode(id)
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
		c.application.MarkBlacklisted(candidate, message)
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

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
