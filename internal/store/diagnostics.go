package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ipCacheEntry struct {
	Owner    string `json:"owner"`
	ASN      string `json:"asn"`
	ASName   string `json:"as_name"`
	Location string `json:"location"`
	IPType   string `json:"ip_type"`
	Quality  string `json:"quality"`
	CachedAt int64  `json:"cached_at"`
}

type ipAPIResult struct {
	Status     string `json:"status"`
	Query      string `json:"query"`
	Country    string `json:"country"`
	RegionName string `json:"regionName"`
	City       string `json:"city"`
	ISP        string `json:"isp"`
	Org        string `json:"org"`
	AS         string `json:"as"`
	ASName     string `json:"asname"`
	Proxy      bool   `json:"proxy"`
	Hosting    bool   `json:"hosting"`
	Mobile     bool   `json:"mobile"`
}

// EnrichIPInfo 批量查询节点 IP 的归属信息。
func (s *Store) EnrichIPInfo(ctx context.Context, nodes []Node) {
	cache := map[string]ipCacheEntry{}
	cachePath := filepath.Join(s.Config.DataDir, "ip_cache.json")
	_ = readJSON(cachePath, &cache)
	now := time.Now().Unix()
	missing := make([]string, 0)
	seen := map[string]bool{}
	for index := range nodes {
		ip := FirstNonEmpty(nodes[index].IP, nodes[index].RemoteHost)
		if entry, ok := cache[ip]; ok && now-entry.CachedAt < int64((7*24*time.Hour).Seconds()) {
			applyIPInfo(&nodes[index], entry)
			continue
		}
		if net.ParseIP(ip) != nil && !seen[ip] {
			missing = append(missing, ip)
			seen[ip] = true
		}
	}
	transport := &http.Transport{}
	if proxyURL, err := ParseProxyURL(Getenv("UPSTREAM_PROXY")); err == nil && proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport}
	for start := 0; start < len(missing); start += 100 {
		end := start + 100
		if end > len(missing) {
			end = len(missing)
		}
		payload, _ := json.Marshal(missing[start:end])
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://ip-api.com/batch?lang=zh-CN&fields=status,query,country,regionName,city,isp,org,as,asname,proxy,hosting,mobile", bytes.NewReader(payload))
		if err != nil {
			continue
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "gatepilot-go/1.0")
		response, err := client.Do(request)
		if err != nil {
			s.LogEvent("warning", "IPInfo", "IP 信息查询失败: "+err.Error())
			continue
		}
		var results []ipAPIResult
		err = json.NewDecoder(response.Body).Decode(&results)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			continue
		}
		for _, result := range results {
			if result.Status != "success" || result.Query == "" {
				continue
			}
			entry := ipCacheEntry{
				Owner: FirstNonEmpty(result.Org, result.ISP), ASN: result.AS, ASName: result.ASName,
				Location: strings.TrimSpace(strings.Join(nonEmptyStrings(result.Country, result.RegionName, result.City), " ")),
				IPType:   "residential", Quality: "normal", CachedAt: now,
			}
			if result.Mobile {
				entry.IPType, entry.Quality = "mobile", "mobile"
			} else if result.Hosting || result.Proxy {
				entry.IPType = "hosting"
				if result.Proxy {
					entry.Quality = "proxy"
				} else {
					entry.Quality = "datacenter"
				}
			}
			cache[result.Query] = entry
		}
	}
	_ = writeJSON(cachePath, cache)
	for index := range nodes {
		if entry, ok := cache[FirstNonEmpty(nodes[index].IP, nodes[index].RemoteHost)]; ok {
			applyIPInfo(&nodes[index], entry)
		}
	}
}

func applyIPInfo(candidate *Node, entry ipCacheEntry) {
	candidate.Owner = entry.Owner
	candidate.ASN = entry.ASN
	candidate.ASName = entry.ASName
	candidate.Location = entry.Location
	candidate.IPType = entry.IPType
	candidate.Quality = entry.Quality
}

func nonEmptyStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			result = append(result, strings.TrimSpace(value))
		}
	}
	return result
}

// DiagnoseAPIFailure 诊断 API 连接失败原因。
func DiagnoseAPIFailure(endpoint string, cause error) (string, string) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return "ERR_API_URL", "[ERR_API_URL] VPNGate API 地址无效"
	}
	if _, err := net.DefaultResolver.LookupHost(context.Background(), parsed.Hostname()); err != nil {
		return "ERR_API_DNS", "[ERR_API_DNS] 无法解析 VPNGate API 域名，请检查 DNS 或上游代理"
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(parsed.Hostname(), port), 5*time.Second)
	if err != nil {
		return "ERR_API_CONNECT", "[ERR_API_CONNECT] 可以解析域名，但无法连接 VPNGate API 端口，请检查 VPS 出站防火墙"
	}
	_ = connection.Close()
	if cause != nil && strings.Contains(strings.ToLower(cause.Error()), "certificate") {
		return "ERR_API_TLS", "[ERR_API_TLS] VPNGate API TLS 证书校验失败，程序已尝试兼容回退"
	}
	return "ERR_API_HTTP", fmt.Sprintf("[ERR_API_HTTP] VPNGate API 请求失败: %v", cause)
}

// DiagnoseOpenVPNFailure 诊断 OpenVPN 连接失败原因。
func DiagnoseOpenVPNFailure(output string, cause error) (string, string) {
	causeText := ""
	if cause != nil {
		causeText = cause.Error()
	}
	lower := strings.ToLower(output + "\n" + causeText)
	switch {
	case errors.Is(cause, exec.ErrNotFound) || errors.Is(cause, os.ErrNotExist) || strings.Contains(lower, "executable file not found") || strings.Contains(lower, "cannot find the file specified"):
		return "ERR_VPN_EXEC", "找不到 OpenVPN 核心程序；请将 openvpn.exe 和配套 DLL 放入 GatePilot 旁的 openvpn 目录"
	case strings.Contains(lower, "specified module could not be found") || strings.Contains(lower, "missing dll"):
		return "ERR_VPN_DLL", "OpenVPN 核心目录缺少配套 DLL，请从同一版本、同一架构的 OpenVPN 包中一起复制"
	case strings.Contains(lower, "access is denied") || strings.Contains(lower, "requested operation requires elevation") || strings.Contains(lower, "administrator privileges") || strings.Contains(lower, "requires system privileges") || strings.Contains(lower, "interactive service"):
		return "ERR_VPN_PERMISSION", "OpenVPN 没有足够权限创建虚拟网卡；请以管理员/SYSTEM 身份运行 GatePilot，或安装并启动 OpenVPN Interactive Service"
	case strings.Contains(lower, "auth_failed"):
		return "ERR_VPN_AUTH", "OpenVPN 认证失败"
	case strings.Contains(lower, "tls error") || strings.Contains(lower, "tls key negotiation"):
		return "ERR_VPN_TLS", "OpenVPN TLS 握手失败，节点可能已失效或链路被阻断"
	case strings.Contains(lower, "connection refused"):
		return "ERR_VPN_REFUSED", "OpenVPN 服务端拒绝连接"
	case strings.Contains(lower, "network is unreachable") || strings.Contains(lower, "no route to host"):
		return "ERR_VPN_ROUTE", "服务器到 VPN 节点的网络路由不可达"
	case strings.Contains(lower, "cannot open tun") || strings.Contains(lower, "tun/tap") && strings.Contains(lower, "failed") || strings.Contains(lower, "no tap-windows adapters") || strings.Contains(lower, "failed to open wintun") || strings.Contains(lower, "tap-windows6 adapters on this system"):
		return "ERR_VPN_DRIVER", "无法打开 OpenVPN 虚拟网卡；Windows 请以管理员/SYSTEM 权限运行，或准备可用的 Wintun/TAP/DCO 驱动，Linux 请检查 /dev/net/tun"
	case strings.Contains(lower, "options error") || strings.Contains(lower, "unrecognized option"):
		return "ERR_VPN_CONFIG", "OpenVPN 配置或版本不兼容"
	case errors.Is(cause, context.DeadlineExceeded):
		return "ERR_VPN_TIMEOUT", "OpenVPN 连接超时"
	default:
		return "ERR_VPN_UNKNOWN", fmt.Sprintf("OpenVPN 启动失败: %v", cause)
	}
}

// LocalObstructionDiagnosis 诊断本机网络连通性。
func LocalObstructionDiagnosis(config AppConfig) string {
	if _, err := os.Stat("/dev/net/tun"); err != nil && os.PathSeparator == '/' {
		return "未检测到 /dev/net/tun"
	}
	probeHost := config.ProxyHost
	if probeHost == "" || probeHost == "0.0.0.0" || probeHost == "::" {
		probeHost = "127.0.0.1"
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(probeHost, fmt.Sprintf("%d", config.ProxyPort)), 750*time.Millisecond)
	if err != nil {
		return "本地代理端口未监听: " + err.Error()
	}
	_ = connection.Close()
	return ""
}

// Getenv 读取并修剪环境变量。
func Getenv(name string) string {
	return strings.TrimSpace(EnvString(name, ""))
}
