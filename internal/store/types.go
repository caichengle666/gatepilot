package store

import "time"

const DefaultSpeedTestURL = "https://speed.cloudflare.com/__down?bytes=10000000"

// Node 表示一个 VPNGate OpenVPN 节点。
type Node struct {
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

// AppConfig 是应用启动配置，来自环境变量。
type AppConfig struct {
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

// UIConfig 是 Web 管理界面的运行时配置，持久化到磁盘。
type UIConfig struct {
	Username          string   `json:"username"`
	SecretPath        string   `json:"secret_path"`
	Password          string   `json:"password"`
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	ProxyPort         int      `json:"proxy_port"`
	ProxyAuthEnabled  bool     `json:"proxy_auth_enabled"`
	ProxyUsername     string   `json:"proxy_username"`
	ProxyPassword     string   `json:"proxy_password"`
	UpstreamProxy     string   `json:"upstream_proxy"`
	SpeedTestURL      string   `json:"speed_test_url"`
	RoutingMode       string   `json:"routing_mode"`
	ForceCountry      string   `json:"force_country"`
	RoutingIPType     string   `json:"routing_ip_type"`
	ConnectionEnabled bool     `json:"connection_enabled"`
	FixedNodeID       string   `json:"fixed_node_id"`
	FavoriteNodeIDs   []string `json:"favorite_node_ids"`
	FavoriteFallback  bool     `json:"fav_fail_fallback"`
	SplitRouting      bool     `json:"split_routing"`
	SplitRules        []SplitRule `json:"split_rules,omitempty"`
	SplitDefault      string   `json:"split_default"`
}

// RuntimeState 是运行时状态，部分持久化。
type RuntimeState struct {
	Status               string `json:"status"`
	Message              string `json:"message"`
	ActiveNodeID         string `json:"active_node_id"`
	ActiveOpenVPNNodeID  string `json:"active_openvpn_node_id"`
	ActiveNodeLatency    string `json:"active_node_latency"`
	IsConnecting         bool   `json:"is_connecting"`
	MaintenanceRunning   bool   `json:"maintenance_running"`
	APIURL               string `json:"api_url"`
	TargetValidNodes     int    `json:"target_valid_nodes"`
	FetchIntervalSeconds int64  `json:"fetch_interval_seconds"`
	CheckIntervalSeconds int64  `json:"check_interval_seconds"`
	LocalProxy           string `json:"local_proxy"`
	LastFetchAt          int64  `json:"last_fetch_at,omitempty"`
	LastFetchStatus      string `json:"last_fetch_status"`
	LastFetchMessage     string `json:"last_fetch_message"`
	LastFetchErrorCode   string `json:"last_fetch_error_code,omitempty"`
	LastCheckAt          int64  `json:"last_check_at,omitempty"`
	LastCheckMessage     string `json:"last_check_message"`
	ValidNodes           int    `json:"valid_nodes"`
	BlacklistedNodes     int    `json:"blacklisted_nodes"`
	ProxyOK              bool   `json:"proxy_ok"`
	ProxyIP              string `json:"proxy_ip"`
	ProxyLatencyMS       int64  `json:"proxy_latency_ms"`
	ProxyError           string `json:"proxy_error"`
	CollectorHeartbeat   int64  `json:"collector_heartbeat,omitempty"`
	CheckerHeartbeat     int64  `json:"checker_heartbeat,omitempty"`
	PingerHeartbeat      int64  `json:"pinger_heartbeat,omitempty"`
	OpenVPNOK            bool   `json:"openvpn_ok"`
	OpenVPNMessage       string `json:"openvpn_message,omitempty"`
	UpdatedAt            string `json:"updated_at"`
}

// LogEntry 是一条结构化日志。
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Module    string `json:"module"`
	Message   string `json:"message"`
}

// BlacklistEntry 是黑名单中的一条记录。
type BlacklistEntry struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Reason   string `json:"reason"`
	MarkedAt int64  `json:"marked_at"`
	Until    int64  `json:"until"`
}

// SplitRule 是一条分流规则配置。
type SplitRule struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action string `json:"action"`
}
