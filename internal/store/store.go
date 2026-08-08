package store

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultAPIURL = "https://www.vpngate.net/api/iphone/"

// Store 是核心状态容器，持有配置、UI 设置、运行状态和节点列表。
type Store struct {
	mu     sync.RWMutex
	Config AppConfig
	UI     UIConfig
	State  RuntimeState
	Nodes  []Node
}

var jsonWriteMu sync.Mutex

// LoadAppConfig 从环境变量加载应用配置。
func LoadAppConfig() AppConfig {
	executable, _ := os.Executable()
	root := filepath.Join(filepath.Dir(executable), "vpngate_data")
	if value := strings.TrimSpace(os.Getenv("VPNGATE_DATA_DIR")); value != "" {
		root = value
	}
	proxyPort := EnvInt("LOCAL_PROXY_PORT", 7928, 1, 65535)
	tunnelProxyPortStart := EnvInt("LOCAL_PROXY_TUNNEL_PORT_START", 7929, 1, 65528)
	return AppConfig{
		APIURL:                        EnvString("VPNGATE_API_URL", defaultAPIURL),
		DataDir:                       root,
		OpenVPNCommand:                EnvString("OPENVPN_CMD", DefaultOpenVPNCommand()),
		OpenVPNUser:                   EnvString("OPENVPN_AUTH_USER", "vpn"),
		OpenVPNPassword:               EnvString("OPENVPN_AUTH_PASS", "vpn"),
		ProxyHost:                     EnvString("LOCAL_PROXY_HOST", "127.0.0.1"),
		ProxyPort:                     proxyPort,
		ProxyPublishedPort:            EnvInt("LOCAL_PROXY_PUBLISHED_PORT", proxyPort, 1, 65535),
		TunnelProxyPortStart:          tunnelProxyPortStart,
		TunnelProxyPublishedPortStart: EnvInt("LOCAL_PROXY_TUNNEL_PUBLISHED_PORT_START", tunnelProxyPortStart, 1, 65528),
		ProxyMaxConnections:           EnvInt("LOCAL_PROXY_MAX_CONNECTIONS", 256, 1, 65535),
		UIHost:                        EnvString("UI_HOST", "127.0.0.1"),
		UIPort:                        EnvInt("UI_PORT", 8787, 1, 65535),
		FetchInterval:                 time.Duration(EnvInt("FETCH_INTERVAL_SECONDS", 1260, 1, 86400)) * time.Second,
		ReconnectInterval:             time.Duration(EnvInt("RECONNECT_INTERVAL_SECONDS", 15, 1, 3600)) * time.Second,
		OpenVPNTimeout:                time.Duration(EnvInt("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 3, 600)) * time.Second,
		TargetValidNodes:              EnvInt("TARGET_VALID_NODES", 3, 1, 100),
		MaxScanRows:                   EnvInt("MAX_SCAN_ROWS", 300, 1, 10000),
		InvalidBackoff:                time.Duration(EnvInt("INVALID_BACKOFF_SECONDS", 1800, 1, 86400)) * time.Second,
		ManualTestNodeLimit:           EnvInt("MANUAL_TEST_NODE_LIMIT", 5, 1, 20),
		InitialTestLimit:              EnvInt("INITIAL_CONNECT_TEST_LIMIT", 10, 1, 50),
		DisableBackground:             EnvBool("DISABLE_BACKGROUND_FETCH", false),
	}
}

// ProxyHostIsLocal 判断代理监听地址是否只面向本机。
func ProxyHostIsLocal(host string) bool {
	switch strings.TrimSpace(strings.ToLower(host)) {
	case "", "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	default:
		return false
	}
}

// ProxyCredentials 返回最终生效的代理认证凭据。
func ProxyCredentials(ui UIConfig) (username, password string, enabled bool) {
	username = strings.TrimSpace(EnvString("LOCAL_PROXY_USER", Getenv("LOCAL_PROXY_USERNAME")))
	password = strings.TrimSpace(EnvString("LOCAL_PROXY_PASS", Getenv("LOCAL_PROXY_PASSWORD")))
	if username != "" || password != "" {
		return username, password, true
	}
	if ui.ProxyAuthEnabled {
		return strings.TrimSpace(ui.ProxyUsername), ui.ProxyPassword, true
	}
	return "", "", false
}

// ValidateProxyAuth 校验代理监听地址和认证配置是否安全。
func ValidateProxyAuth(host string, ui UIConfig) error {
	_, _, enabled := ProxyCredentials(ui)
	publishedHost := strings.TrimSpace(os.Getenv("LOCAL_PROXY_PUBLISHED_HOST"))
	publishedLocally := publishedHost != "" && ProxyHostIsLocal(publishedHost)
	if !ProxyHostIsLocal(host) && !publishedLocally && !enabled {
		return errors.New("代理监听非本机地址时，必须启用代理认证")
	}
	if enabled {
		username, password, _ := ProxyCredentials(ui)
		if username == "" || password == "" {
			return errors.New("启用代理认证时，用户名和密码都不能为空")
		}
	}
	return nil
}

// EnvString 读取字符串环境变量。
func EnvString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// EnvInt 读取整数环境变量，带范围约束。
func EnvInt(name string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

// EnvBool 读取布尔环境变量。
func EnvBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func randomCredential(length int) string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buffer := make([]byte, length)
	random := make([]byte, length)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("admin%d", time.Now().UnixNano())
	}
	for index := range buffer {
		buffer[index] = alphabet[int(random[index])%len(alphabet)]
	}
	return string(buffer)
}

// New 创建 Store 实例，初始化数据目录并加载持久化状态。
func New(config AppConfig) (*Store, error) {
	if err := os.MkdirAll(config.DataDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(config.DataDir, "configs"), 0o755); err != nil {
		return nil, err
	}
	ui := UIConfig{
		Username:          randomCredential(12),
		SecretPath:        randomCredential(12),
		Password:          randomCredential(12),
		Host:              config.UIHost,
		Port:              config.UIPort,
		ProxyPort:         config.ProxyPort,
		UpstreamProxy:     strings.TrimSpace(os.Getenv("UPSTREAM_PROXY")),
		SpeedTestURL:      DefaultSpeedTestURL,
		RoutingMode:       "auto",
		RoutingIPType:     "all",
		ConnectionEnabled: true,
		FavoriteNodeIDs:   []string{},
	}
	_ = readJSON(filepath.Join(config.DataDir, "ui_auth.json"), &ui)
	if ui.Port < 1 || ui.Port > 65535 {
		ui.Port = config.UIPort
	}
	if ui.ProxyPort < 1 || ui.ProxyPort > 65535 || ui.ProxyPort == ui.Port {
		ui.ProxyPort = config.ProxyPort
	}
	if ui.Username == "" {
		ui.Username = randomCredential(12)
	}
	if ui.Password == "" {
		ui.Password = randomCredential(12)
	}
	if ui.SecretPath == "" {
		ui.SecretPath = randomCredential(12)
	}
	if ui.SpeedTestURL == "" {
		ui.SpeedTestURL = DefaultSpeedTestURL
	}
	config.UIHost, config.UIPort, config.ProxyPort = ui.Host, ui.Port, ui.ProxyPort
	application := &Store{
		Config: config,
		UI:     ui,
		State: RuntimeState{
			Status: "disconnected", Message: "尚未连接 VPN", ActiveNodeLatency: "无活动连接",
			APIURL: config.APIURL, TargetValidNodes: config.TargetValidNodes,
			FetchIntervalSeconds: int64(config.FetchInterval.Seconds()), CheckIntervalSeconds: int64(config.FetchInterval.Seconds()),
			LocalProxy: ProxyDisplay(config.ProxyHost, config.ProxyPort), LastFetchStatus: "not_started",
			ProxyIP: "-", UpdatedAt: time.Now().Format(time.RFC3339),
		},
		Nodes: []Node{},
	}
	_ = readJSON(filepath.Join(config.DataDir, "state.json"), &application.State)
	_ = readJSON(filepath.Join(config.DataDir, "nodes.json"), &application.Nodes)
	application.State.Status = "disconnected"
	application.State.Message = "尚未连接 VPN"
	application.State.ActiveNodeID = ""
	application.State.ActiveOpenVPNNodeID = ""
	application.State.ActiveNodeLatency = "无活动连接"
	application.State.IsConnecting = false
	application.State.MaintenanceRunning = false
	application.State.ProxyOK = false
	application.State.ProxyIP = "-"
	application.State.ProxyLatencyMS = 0
	application.State.ProxyError = ""
	for index := range application.Nodes {
		application.Nodes[index].Active = false
	}
	if err := application.SaveUI(); err != nil {
		return nil, err
	}
	auth := []byte(config.OpenVPNUser + "\n" + config.OpenVPNPassword + "\n")
	if err := os.WriteFile(filepath.Join(config.DataDir, "vpngate_auth.txt"), auth, 0o600); err != nil {
		return nil, err
	}
	return application, nil
}

func readJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func writeJSON(path string, value any) error {
	jsonWriteMu.Lock()
	defer jsonWriteMu.Unlock()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err == nil {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(temporary, path)
}

// SaveUI 持久化 UI 配置。
func (s *Store) SaveUI() error {
	s.mu.RLock()
	value := s.UI
	s.mu.RUnlock()
	return writeJSON(filepath.Join(s.Config.DataDir, "ui_auth.json"), value)
}

// SaveNodes 持久化节点列表。
func (s *Store) SaveNodes() error {
	s.mu.RLock()
	value := append([]Node(nil), s.Nodes...)
	s.mu.RUnlock()
	return writeJSON(filepath.Join(s.Config.DataDir, "nodes.json"), value)
}

// SetState 设置连接状态并持久化。
func (s *Store) SetState(status, message, activeNodeID string) error {
	s.mu.Lock()
	s.State.Status = status
	s.State.Message = message
	s.State.ActiveNodeID = activeNodeID
	s.State.ActiveOpenVPNNodeID = activeNodeID
	s.State.IsConnecting = status == "connecting"
	s.State.UpdatedAt = time.Now().Format(time.RFC3339)
	for index := range s.Nodes {
		s.Nodes[index].Active = s.Nodes[index].ID == activeNodeID
	}
	value := s.State
	s.mu.Unlock()
	return writeJSON(filepath.Join(s.Config.DataDir, "state.json"), value)
}

// UpdateState 原子更新运行状态并持久化。
func (s *Store) UpdateState(update func(*RuntimeState)) error {
	s.mu.Lock()
	update(&s.State)
	s.State.ActiveOpenVPNNodeID = s.State.ActiveNodeID
	s.State.UpdatedAt = time.Now().Format(time.RFC3339)
	value := s.State
	s.mu.Unlock()
	return writeJSON(filepath.Join(s.Config.DataDir, "state.json"), value)
}

// ProxyDisplay 格式化代理地址。
func ProxyDisplay(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + strconv.Itoa(port)
}

// Snapshot 返回当前 UI 配置、运行状态和节点列表的副本。
func (s *Store) Snapshot() (UIConfig, RuntimeState, []Node) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.UI, s.State, append([]Node(nil), s.Nodes...)
}

// UpstreamProxy 返回当前上游代理地址。
func (s *Store) UpstreamProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.UI.UpstreamProxy
}

// NodeByID 按 ID 查找节点。
func (s *Store) NodeByID(id string) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, candidate := range s.Nodes {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return Node{}, false
}

// UpdateUI 在写锁下修改 UI 配置并持久化。fn 返回错误则放弃修改。
func (s *Store) UpdateUI(fn func(ui *UIConfig) error) error {
	s.mu.Lock()
	if err := fn(&s.UI); err != nil {
		s.mu.Unlock()
		return err
	}
	value := s.UI
	s.mu.Unlock()
	return writeJSON(filepath.Join(s.Config.DataDir, "ui_auth.json"), value)
}

// MutateUI 在写锁下修改 UI 配置，并提供同一时刻的运行状态。
func (s *Store) MutateUI(fn func(ui *UIConfig, state RuntimeState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&s.UI, s.State)
}

// SetConnectionEnabled 设置自动连接开关并持久化。
func (s *Store) SetConnectionEnabled(enabled bool) {
	s.mu.Lock()
	s.UI.ConnectionEnabled = enabled
	value := s.UI
	s.mu.Unlock()
	_ = writeJSON(filepath.Join(s.Config.DataDir, "ui_auth.json"), value)
}

// EnableConnectionFor 启用自动连接，固定 IP 模式下同时锁定节点。
func (s *Store) EnableConnectionFor(candidate Node) {
	s.mu.Lock()
	s.UI.ConnectionEnabled = true
	if s.UI.RoutingMode == "fixed_ip" {
		s.UI.FixedNodeID = candidate.ID
	}
	s.mu.Unlock()
}

// UpdateNodeProbe 更新节点探测结果并重新排序。
func (s *Store) UpdateNodeProbe(id string, available bool, latency int64, message string) {
	s.mu.Lock()
	for index := range s.Nodes {
		if s.Nodes[index].ID != id {
			continue
		}
		if message == "正在检测节点连通性..." {
			s.Nodes[index].ProbeStatus = "testing"
		} else if available {
			s.Nodes[index].ProbeStatus = "available"
		} else {
			s.Nodes[index].ProbeStatus = "unavailable"
		}
		s.Nodes[index].ProbeMessage = message
		s.Nodes[index].ProbedAt = time.Now().Unix()
		s.Nodes[index].LatencyMS = latency
	}
	s.Nodes = SortNodes(s.Nodes)
	s.mu.Unlock()
	_ = s.SaveNodes()
}

// NetDialTimeout 拨号到指定主机端口。
func NetDialTimeout(network, host string, port int, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, net.JoinHostPort(host, strconv.Itoa(port)), timeout)
}
