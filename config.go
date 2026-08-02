package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultAPIURL = "https://www.vpngate.net/api/iphone/"

type appConfig struct {
	APIURL              string
	DataDir             string
	OpenVPNCommand      string
	OpenVPNUser         string
	OpenVPNPassword     string
	ProxyHost           string
	ProxyPort           int
	ProxyMaxConnections int
	UIHost              string
	UIPort              int
	FetchInterval       time.Duration
	ReconnectInterval   time.Duration
	OpenVPNTimeout      time.Duration
	TargetValidNodes    int
	MaxScanRows         int
	InvalidBackoff      time.Duration
	ManualTestNodeLimit int
	InitialTestLimit    int
	DisableBackground   bool
}

type node struct {
	ID           string `json:"id"`
	Country      string `json:"country"`
	CountryShort string `json:"country_short"`
	HostName     string `json:"host_name"`
	IP           string `json:"ip"`
	Score        int64  `json:"score"`
	Ping         int64  `json:"ping"`
	Speed        int64  `json:"speed"`
	Sessions     int64  `json:"sessions"`
	Owner        string `json:"owner"`
	ASN          string `json:"asn"`
	ASName       string `json:"as_name"`
	Location     string `json:"location"`
	IPType       string `json:"ip_type"`
	Quality      string `json:"quality"`
	TotalUsers   int64  `json:"total_users"`
	TotalTraffic int64  `json:"total_traffic"`
	LogType      string `json:"log_type"`
	Message      string `json:"message"`
	ConfigText   string `json:"config_text,omitempty"`
	ConfigFile   string `json:"config_file"`
	RemoteHost   string `json:"remote_host"`
	RemotePort   int    `json:"remote_port"`
	Protocol     string `json:"proto"`
	ProbeStatus  string `json:"probe_status"`
	ProbeMessage string `json:"probe_message"`
	FetchedAt    int64  `json:"fetched_at"`
	ProbedAt     int64  `json:"probed_at"`
	LatencyMS    int64  `json:"latency_ms"`
	Active       bool   `json:"active"`
}

type uiConfig struct {
	Username          string   `json:"username"`
	SecretPath        string   `json:"secret_path"`
	Password          string   `json:"password"`
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	ProxyPort         int      `json:"proxy_port"`
	UpstreamProxy     string   `json:"upstream_proxy"`
	SpeedTestURL      string   `json:"speed_test_url"`
	RoutingMode       string   `json:"routing_mode"`
	ForceCountry      string   `json:"force_country"`
	RoutingIPType     string   `json:"routing_ip_type"`
	ConnectionEnabled bool     `json:"connection_enabled"`
	FixedNodeID       string   `json:"fixed_node_id"`
	FavoriteNodeIDs   []string `json:"favorite_node_ids"`
	FavoriteFallback  bool     `json:"fav_fail_fallback"`
}

type runtimeState struct {
	Status               string  `json:"status"`
	Message              string  `json:"message"`
	ActiveNodeID         string  `json:"active_node_id"`
	ActiveOpenVPNNodeID  string  `json:"active_openvpn_node_id"`
	ActiveNodeLatency    string  `json:"active_node_latency"`
	IsConnecting         bool    `json:"is_connecting"`
	MaintenanceRunning   bool    `json:"maintenance_running"`
	APIURL               string  `json:"api_url"`
	TargetValidNodes     int     `json:"target_valid_nodes"`
	FetchIntervalSeconds int64   `json:"fetch_interval_seconds"`
	CheckIntervalSeconds int64   `json:"check_interval_seconds"`
	LocalProxy           string  `json:"local_proxy"`
	LastFetchAt          int64   `json:"last_fetch_at,omitempty"`
	LastFetchStatus      string  `json:"last_fetch_status"`
	LastFetchMessage     string  `json:"last_fetch_message"`
	LastFetchErrorCode   string  `json:"last_fetch_error_code,omitempty"`
	LastCheckAt          int64   `json:"last_check_at,omitempty"`
	LastCheckMessage     string  `json:"last_check_message"`
	ValidNodes           int     `json:"valid_nodes"`
	BlacklistedNodes     int     `json:"blacklisted_nodes"`
	ProxyOK              bool    `json:"proxy_ok"`
	ProxyIP              string  `json:"proxy_ip"`
	ProxyLatencyMS       int64   `json:"proxy_latency_ms"`
	ProxySpeedMbps       float64 `json:"proxy_speed_mbps"`
	ProxyError           string  `json:"proxy_error"`
	CollectorHeartbeat   int64   `json:"collector_heartbeat,omitempty"`
	CheckerHeartbeat     int64   `json:"checker_heartbeat,omitempty"`
	PingerHeartbeat      int64   `json:"pinger_heartbeat,omitempty"`
	UpdatedAt            string  `json:"updated_at"`
}

type store struct {
	mu     sync.RWMutex
	config appConfig
	ui     uiConfig
	state  runtimeState
	nodes  []node
}

var jsonWriteMu sync.Mutex

func loadAppConfig() appConfig {
	executable, _ := os.Executable()
	root := filepath.Join(filepath.Dir(executable), "vpngate_data")
	if value := strings.TrimSpace(os.Getenv("VPNGATE_DATA_DIR")); value != "" {
		root = value
	}
	return appConfig{
		APIURL:              envString("VPNGATE_API_URL", defaultAPIURL),
		DataDir:             root,
		OpenVPNCommand:      envString("OPENVPN_CMD", defaultOpenVPNCommand()),
		OpenVPNUser:         envString("OPENVPN_AUTH_USER", "vpn"),
		OpenVPNPassword:     envString("OPENVPN_AUTH_PASS", "vpn"),
		ProxyHost:           envString("LOCAL_PROXY_HOST", "127.0.0.1"),
		ProxyPort:           envInt("LOCAL_PROXY_PORT", 7928, 1, 65535),
		ProxyMaxConnections: envInt("LOCAL_PROXY_MAX_CONNECTIONS", 256, 1, 65535),
		UIHost:              envString("UI_HOST", "::"),
		UIPort:              envInt("UI_PORT", 8787, 1, 65535),
		FetchInterval:       time.Duration(envInt("FETCH_INTERVAL_SECONDS", 1260, 1, 86400)) * time.Second,
		ReconnectInterval:   time.Duration(envInt("RECONNECT_INTERVAL_SECONDS", 15, 1, 3600)) * time.Second,
		OpenVPNTimeout:      time.Duration(envInt("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 3, 600)) * time.Second,
		TargetValidNodes:    envInt("TARGET_VALID_NODES", 3, 1, 100),
		MaxScanRows:         envInt("MAX_SCAN_ROWS", 300, 1, 10000),
		InvalidBackoff:      time.Duration(envInt("INVALID_BACKOFF_SECONDS", 1800, 1, 86400)) * time.Second,
		ManualTestNodeLimit: envInt("MANUAL_TEST_NODE_LIMIT", 5, 1, 20),
		InitialTestLimit:    envInt("INITIAL_CONNECT_TEST_LIMIT", 10, 1, 50),
		DisableBackground:   envBool("DISABLE_BACKGROUND_FETCH", false),
	}
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
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

func newStore(config appConfig) (*store, error) {
	if err := os.MkdirAll(filepath.Join(config.DataDir, "configs"), 0o755); err != nil {
		return nil, err
	}
	ui := uiConfig{
		Username:          randomCredential(12),
		SecretPath:        randomCredential(12),
		Password:          randomCredential(12),
		Host:              config.UIHost,
		Port:              config.UIPort,
		ProxyPort:         config.ProxyPort,
		UpstreamProxy:     strings.TrimSpace(os.Getenv("UPSTREAM_PROXY")),
		SpeedTestURL:      envString("SPEED_TEST_URL", "https://speed.cloudflare.com/__down?bytes=10000000"),
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
	config.UIHost, config.UIPort, config.ProxyPort = ui.Host, ui.Port, ui.ProxyPort
	application := &store{
		config: config,
		ui:     ui,
		state: runtimeState{
			Status: "disconnected", Message: "尚未连接 VPN", ActiveNodeLatency: "无活动连接",
			APIURL: config.APIURL, TargetValidNodes: config.TargetValidNodes,
			FetchIntervalSeconds: int64(config.FetchInterval.Seconds()), CheckIntervalSeconds: int64(config.FetchInterval.Seconds()),
			LocalProxy: proxyDisplay(config.ProxyHost, config.ProxyPort), LastFetchStatus: "not_started",
			ProxyIP: "-", UpdatedAt: time.Now().Format(time.RFC3339),
		},
		nodes: []node{},
	}
	_ = readJSON(filepath.Join(config.DataDir, "state.json"), &application.state)
	_ = readJSON(filepath.Join(config.DataDir, "nodes.json"), &application.nodes)
	application.state.Status = "disconnected"
	application.state.Message = "尚未连接 VPN"
	application.state.ActiveNodeID = ""
	application.state.ActiveOpenVPNNodeID = ""
	application.state.ActiveNodeLatency = "无活动连接"
	application.state.IsConnecting = false
	application.state.MaintenanceRunning = false
	application.state.ProxyOK = false
	application.state.ProxyIP = "-"
	application.state.ProxyLatencyMS = 0
	application.state.ProxyError = ""
	for index := range application.nodes {
		application.nodes[index].Active = false
	}
	if err := application.saveUI(); err != nil {
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

func (application *store) saveUI() error {
	application.mu.RLock()
	value := application.ui
	application.mu.RUnlock()
	return writeJSON(filepath.Join(application.config.DataDir, "ui_auth.json"), value)
}

func (application *store) saveNodes() error {
	application.mu.RLock()
	value := append([]node(nil), application.nodes...)
	application.mu.RUnlock()
	return writeJSON(filepath.Join(application.config.DataDir, "nodes.json"), value)
}

func (application *store) setState(status, message, activeNodeID string) error {
	application.mu.Lock()
	application.state.Status = status
	application.state.Message = message
	application.state.ActiveNodeID = activeNodeID
	application.state.ActiveOpenVPNNodeID = activeNodeID
	application.state.IsConnecting = status == "connecting"
	application.state.UpdatedAt = time.Now().Format(time.RFC3339)
	for index := range application.nodes {
		application.nodes[index].Active = application.nodes[index].ID == activeNodeID
	}
	value := application.state
	application.mu.Unlock()
	return writeJSON(filepath.Join(application.config.DataDir, "state.json"), value)
}

func (application *store) updateState(update func(*runtimeState)) error {
	application.mu.Lock()
	update(&application.state)
	application.state.ActiveOpenVPNNodeID = application.state.ActiveNodeID
	application.state.UpdatedAt = time.Now().Format(time.RFC3339)
	value := application.state
	application.mu.Unlock()
	return writeJSON(filepath.Join(application.config.DataDir, "state.json"), value)
}

func proxyDisplay(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + strconv.Itoa(port)
}

func (application *store) snapshot() (uiConfig, runtimeState, []node) {
	application.mu.RLock()
	defer application.mu.RUnlock()
	return application.ui, application.state, append([]node(nil), application.nodes...)
}

func (application *store) upstreamProxy() string {
	application.mu.RLock()
	defer application.mu.RUnlock()
	return application.ui.UpstreamProxy
}

func (application *store) nodeByID(id string) (node, bool) {
	application.mu.RLock()
	defer application.mu.RUnlock()
	for _, candidate := range application.nodes {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return node{}, false
}
