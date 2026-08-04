package store

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var countryTranslations = map[string]string{
	"Japan": "日本", "Korea Republic of": "韩国", "Korea": "韩国",
	"Republic of Korea": "韩国",
	"Thailand":          "泰国", "United States": "美国", "United Kingdom": "英国",
	"Russian Federation": "俄罗斯", "Russian": "俄罗斯", "Viet Nam": "越南", "Vietnam": "越南",
	"China": "中国", "Taiwan": "台湾", "Taiwan Province of China": "台湾", "Hong Kong": "香港",
	"Singapore": "新加坡", "Malaysia": "马来西亚", "Indonesia": "印度尼西亚",
	"India": "印度", "Philippines": "菲律宾", "Australia": "澳大利亚",
	"New Zealand": "新西兰", "Canada": "加拿大", "Ukraine": "乌克兰", "France": "法国",
	"Germany": "德国", "Netherlands": "荷兰", "Sweden": "瑞典", "Norway": "挪威",
	"Spain": "西班牙", "Turkey": "土耳其", "South Africa": "南非", "Brazil": "巴西",
	"Argentina": "阿根廷", "Chile": "智利", "Mexico": "墨西哥", "Egypt": "埃及",
	"Romania": "罗马尼亚", "Poland": "波兰", "Kazakhstan": "哈萨克斯坦", "Georgia": "格鲁吉亚",
	"Mongolia": "蒙古", "Saudi Arabia": "沙特阿拉伯", "Iran": "伊朗", "Iraq": "伊拉克",
	"Colombia": "哥伦比亚", "Cambodia": "柬埔寨", "Ireland": "爱尔兰", "Italy": "意大利",
	"Switzerland": "瑞士", "Belgium": "比利时", "Austria": "奥地利", "Denmark": "丹麦",
	"Finland": "芬兰", "Portugal": "葡萄牙", "Greece": "希腊", "Czech Republic": "捷克",
	"Hungary": "匈牙利", "Israel": "以色列", "United Arab Emirates": "阿联酋", "UAE": "阿联酋",
	"Macao": "澳门", "Macau": "澳门", "Iceland": "冰岛", "Luxembourg": "卢森堡",
}

// RefreshNodes 从 VPNGate API 拉取并更新节点列表。
func (s *Store) RefreshNodes(ctx context.Context) (string, error) {
	s.LogEvent("info", "Main", "开始拉取官方 API 节点列表")
	_ = s.UpdateState(func(state *RuntimeState) {
		state.LastFetchStatus = "running"
		state.LastFetchMessage = "正在拉取 VPNGate 节点"
		state.LastFetchErrorCode = ""
	})
	nodes, fetchMessage, err := s.fetchCandidates(ctx)
	if err != nil {
		code, diagnosis := DiagnoseAPIFailure(s.Config.APIURL, err)
		_ = s.UpdateState(func(state *RuntimeState) {
			state.LastFetchStatus = "error"
			state.LastFetchErrorCode = code
			state.LastFetchMessage = diagnosis
		})
		s.LogEvent("error", "Main", diagnosis)
		return "", err
	}
	if len(nodes) == 0 {
		return "", fmt.Errorf("VPNGate API 没有可用的 OpenVPN 节点")
	}
	s.EnrichIPInfo(ctx, nodes)
	blacklist := s.LoadBlacklist()
	s.mu.Lock()
	activeID := s.State.ActiveNodeID
	oldNodes := make(map[string]Node, len(s.Nodes))
	for _, old := range s.Nodes {
		oldNodes[old.ID] = old
	}
	for index := range nodes {
		if !filepath.IsAbs(nodes[index].ConfigFile) {
			nodes[index].ConfigFile = filepath.Join(s.Config.DataDir, nodes[index].ConfigFile)
		}
		nodes[index].Active = nodes[index].ID == activeID
		if old, ok := oldNodes[nodes[index].ID]; ok {
			nodes[index].ProbeStatus = old.ProbeStatus
			nodes[index].ProbeMessage = old.ProbeMessage
			nodes[index].ProbedAt = old.ProbedAt
			nodes[index].LatencyMS = old.LatencyMS
		}
	}
	nodes = retainActiveNode(nodes, oldNodes, activeID)
	nodes = SortNodes(nodes)
	s.Nodes = nodes
	s.mu.Unlock()
	for index := range nodes {
		if err := os.WriteFile(nodes[index].ConfigFile, []byte(nodes[index].ConfigText), 0o600); err != nil {
			s.LogEvent("warning", "Main", "写入节点配置失败: "+err.Error())
		}
	}
	if err := s.SaveNodes(); err != nil {
		return "", err
	}
	message := fmt.Sprintf("已更新 %d 个 VPNGate OpenVPN 节点（%s）", len(nodes), fetchMessage)
	_ = s.UpdateState(func(state *RuntimeState) {
		state.LastFetchAt = time.Now().Unix()
		state.LastFetchStatus = "ok"
		state.LastFetchMessage = message
		state.BlacklistedNodes = len(blacklist)
	})
	s.LogEvent("info", "Main", message)
	return message, nil
}

func retainActiveNode(nodes []Node, oldNodes map[string]Node, activeID string) []Node {
	if activeID == "" {
		return nodes
	}
	for _, candidate := range nodes {
		if candidate.ID == activeID {
			return nodes
		}
	}
	active, found := oldNodes[activeID]
	if !found {
		return nodes
	}
	active.Active = true
	return append(nodes, active)
}

func (s *Store) fetchCandidates(ctx context.Context) ([]Node, string, error) {
	blacklist := s.LoadBlacklist()
	nodes, lastError := s.fetchAttempt(ctx, s.Config.APIURL)
	if lastError == nil {
		filtered := nodes[:0]
		for _, candidate := range nodes {
			if _, blocked := blacklist[candidate.ID]; !blocked {
				filtered = append(filtered, candidate)
			}
		}
		if len(filtered) > 0 {
			mode := "HTTPS 校验"
			if strings.HasPrefix(s.Config.APIURL, "http://") {
				mode = "用户配置的 HTTP 地址"
			}
			return filtered, mode, nil
		}
		lastError = errors.New("VPNGate API 没有返回未被拉黑的可用 OpenVPN 节点")
	} else {
		s.LogEvent("warning", "Main", fmt.Sprintf("拉取失败 %s: %v", s.Config.APIURL, lastError))
	}
	s.mu.RLock()
	cached := append([]Node(nil), s.Nodes...)
	s.mu.RUnlock()
	if len(cached) > 0 {
		return cached, "本地缓存", nil
	}
	return nil, "", fmt.Errorf("获取 VPNGate 节点失败: %w", lastError)
}

func (s *Store) fetchAttempt(ctx context.Context, endpoint string) ([]Node, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "gatepilot-go/1.0")
	transport := &http.Transport{}
	if proxyURL, proxyErr := ParseProxyURL(s.UpstreamProxy()); proxyErr == nil && proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	client := &http.Client{Timeout: 25 * time.Second, Transport: transport}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPNGate API 返回 %s", response.Status)
	}
	return parseVPNGateCSV(response.Body, s.Config.MaxScanRows)
}

func parseVPNGateCSV(source io.Reader, maximum int) ([]Node, error) {
	data, err := io.ReadAll(io.LimitReader(source, 32<<20))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		if len(filtered) == 0 {
			line = strings.TrimPrefix(line, "#")
		}
		filtered = append(filtered, line)
	}
	reader := csv.NewReader(strings.NewReader(strings.Join(filtered, "\n")))
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return nil, fmt.Errorf("无法解析 VPNGate CSV: %w", err)
	}
	headings := make(map[string]int, len(records[0]))
	for index, heading := range records[0] {
		headings[heading] = index
	}
	result := make([]Node, 0, maximum)
	seen := map[string]bool{}
	for _, record := range records[1:] {
		if len(result) >= maximum {
			break
		}
		candidate, ok := nodeFromRecord(record, headings)
		if !ok || seen[candidate.IP] {
			continue
		}
		seen[candidate.IP] = true
		result = append(result, candidate)
	}
	return result, nil
}

func nodeFromRecord(record []string, headings map[string]int) (Node, bool) {
	value := func(name string) string {
		index, exists := headings[name]
		if !exists || index >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[index])
	}
	hostName := value("HostName")
	ip := value("IP")
	if hostName == "" || ip == "" {
		return Node{}, false
	}
	configData := value("OpenVPN_ConfigData_Base64")
	if configData == "" {
		return Node{}, false
	}
	decoded, err := base64.StdEncoding.DecodeString(configData)
	if err != nil {
		return Node{}, false
	}
	configText := string(decoded)
	remoteHost, remotePort, protocol := parseRemote(configText, ip)
	country := value("CountryLong")
	if translated, ok := countryTranslations[country]; ok {
		country = translated
	}
	configFile := filepath.Join("configs", SafeName(value("CountryShort"))+"_"+SafeName(hostName)+".ovpn")
	return Node{
		ID: value("CountryShort") + "_" + hostName, Country: country, CountryShort: value("CountryShort"),
		HostName: hostName, IP: ip, Score: parseInt64(value("Score")), Ping: parseInt64(value("Ping")),
		Speed: parseInt64(value("Speed")), Sessions: parseInt64(value("NumVpnSessions")),
		TotalUsers: parseInt64(value("TotalUsers")), TotalTraffic: parseInt64(value("TotalTraffic")),
		LogType: value("LogType"), Message: value("Message"), ConfigText: configText,
		ConfigFile: configFile, FetchedAt: time.Now().Unix(),
		RemoteHost: remoteHost, RemotePort: remotePort, Protocol: protocol,
		ProbeStatus: "not_checked",
	}, true
}

func parseRemote(configText, fallbackIP string) (string, int, string) {
	host, port, protocol := fallbackIP, 0, "unknown"
	for _, rawLine := range strings.Split(configText, "\n") {
		fields := strings.Fields(strings.TrimSpace(rawLine))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], ";") {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "proto":
			if len(fields) >= 2 {
				protocol = strings.ToLower(fields[1])
			}
		case "remote":
			if len(fields) >= 3 {
				host = fields[1]
				port, _ = strconv.Atoi(fields[2])
				if len(fields) >= 4 {
					protocol = strings.ToLower(fields[3])
				}
			}
		}
	}
	return host, port, protocol
}

// SafeName 将字符串转为安全的文件名。
func SafeName(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '-' {
			return character
		}
		return '_'
	}, value)
}

func parseInt64(value string) int64 {
	parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed
}

// Candidates 返回经过路由规则过滤和排序的候选节点列表。
func (s *Store) Candidates() []Node {
	ui, _, nodes := s.Snapshot()
	blacklist := s.LoadBlacklist()
	favorites := map[string]bool{}
	for _, id := range ui.FavoriteNodeIDs {
		favorites[id] = true
	}
	filtered := make([]Node, 0, len(nodes))
	for _, candidate := range nodes {
		if _, blocked := blacklist[candidate.ID]; blocked && !candidate.Active {
			continue
		}
		if (ui.RoutingMode == "fixed_country" || ui.RoutingMode == "fixed_region") && ui.ForceCountry != "" && !CountryMatches(candidate, ui.ForceCountry) {
			continue
		}
		if ui.RoutingMode == "fixed_ip" && ui.FixedNodeID != "" && candidate.ID != ui.FixedNodeID {
			continue
		}
		if ui.RoutingMode == "favorites" && !ui.FavoriteFallback && !favorites[candidate.ID] {
			continue
		}
		if ui.RoutingIPType == "residential" && candidate.IPType != "residential" && candidate.IPType != "mobile" && candidate.IPType != "" {
			continue
		}
		if ui.RoutingIPType == "hosting" && candidate.IPType != "hosting" && candidate.IPType != "" {
			continue
		}
		filtered = append(filtered, candidate)
	}
	sort.SliceStable(filtered, func(left, right int) bool {
		leftFavorite, rightFavorite := favorites[filtered[left].ID], favorites[filtered[right].ID]
		if leftFavorite != rightFavorite {
			return leftFavorite
		}
		if filtered[left].ProbeStatus != filtered[right].ProbeStatus {
			return probeRank(filtered[left]) < probeRank(filtered[right])
		}
		leftProtocol, rightProtocol := protocolRank(filtered[left]), protocolRank(filtered[right])
		if leftProtocol != rightProtocol {
			return leftProtocol < rightProtocol
		}
		leftLatency, rightLatency := effectiveLatency(filtered[left]), effectiveLatency(filtered[right])
		if leftLatency != rightLatency {
			return leftLatency < rightLatency
		}
		return filtered[left].Score > filtered[right].Score
	})
	return filtered
}

// SortNodes 按探测状态、IP 类型、延迟和分数排序节点。
func SortNodes(nodes []Node) []Node {
	result := append([]Node(nil), nodes...)
	sort.SliceStable(result, func(left, right int) bool {
		if probeRank(result[left]) != probeRank(result[right]) {
			return probeRank(result[left]) < probeRank(result[right])
		}
		leftPreferred := result[left].IPType == "residential" || result[left].IPType == "mobile"
		rightPreferred := result[right].IPType == "residential" || result[right].IPType == "mobile"
		if leftPreferred != rightPreferred {
			return leftPreferred
		}
		if effectiveLatency(result[left]) != effectiveLatency(result[right]) {
			return effectiveLatency(result[left]) < effectiveLatency(result[right])
		}
		return result[left].Score > result[right].Score
	})
	return result
}

func probeRank(candidate Node) int {
	if candidate.Active || candidate.ProbeStatus == "available" {
		return 0
	}
	if candidate.ProbeStatus == "not_checked" || candidate.ProbeStatus == "testing" || candidate.ProbeStatus == "" {
		return 1
	}
	return 2
}

func protocolRank(candidate Node) int {
	protocol := strings.ToLower(candidate.Protocol)
	if strings.HasPrefix(protocol, "udp") {
		return 0
	}
	if strings.HasPrefix(protocol, "tcp") {
		return 1
	}
	return 2
}

func effectiveLatency(candidate Node) int64 {
	if candidate.LatencyMS > 0 {
		return candidate.LatencyMS
	}
	if candidate.Ping > 0 {
		return candidate.Ping
	}
	return 999999
}

// CountryMatches 判断节点是否匹配目标国家。
func CountryMatches(candidate Node, target string) bool {
	target = strings.TrimSpace(strings.ToLower(target))
	return strings.ToLower(candidate.Country) == target || strings.ToLower(candidate.CountryShort) == target
}

// ToggleFavorite 切换节点收藏状态。
func (s *Store) ToggleFavorite(id string) []string {
	s.mu.Lock()
	found := false
	result := make([]string, 0, len(s.UI.FavoriteNodeIDs)+1)
	for _, current := range s.UI.FavoriteNodeIDs {
		if current == id {
			found = true
			continue
		}
		result = append(result, current)
	}
	if !found {
		result = append(result, id)
	}
	s.UI.FavoriteNodeIDs = result
	s.mu.Unlock()
	_ = s.SaveUI()
	return result
}

// ParseProxyURL 解析代理 URL 字符串。
func ParseProxyURL(raw string) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	return url.Parse(value)
}

// NormalizeProxyURL 校验并规范化代理 URL。
func NormalizeProxyURL(raw string) (string, error) {
	proxyURL, err := ParseProxyURL(raw)
	if err != nil {
		return "", err
	}
	if proxyURL == nil {
		return "", nil
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https", "socks", "socks5":
	default:
		return "", fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
	if proxyURL.Hostname() == "" {
		return "", errors.New("proxy host is required")
	}
	return proxyURL.String(), nil
}

// NormalizeSpeedTestURL 校验并规范化宽带测速地址。
func NormalizeSpeedTestURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return DefaultSpeedTestURL, nil
	}
	if len(value) > 2048 {
		return "", errors.New("speed test URL is too long")
	}
	endpoint, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return "", errors.New("speed test URL must use http or https")
	}
	if endpoint.Hostname() == "" {
		return "", errors.New("speed test host is required")
	}
	return endpoint.String(), nil
}
