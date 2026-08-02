package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
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

func (application *store) refreshNodes(ctx context.Context) (string, error) {
	application.logEvent("info", "Main", "开始拉取官方 API 节点列表")
	_ = application.updateState(func(state *runtimeState) {
		state.LastFetchStatus = "running"
		state.LastFetchMessage = "正在拉取 VPNGate 节点"
		state.LastFetchErrorCode = ""
	})
	nodes, fetchMessage, err := application.fetchCandidates(ctx)
	if err != nil {
		code, diagnosis := diagnoseAPIFailure(application.config.APIURL, err)
		_ = application.updateState(func(state *runtimeState) {
			state.LastFetchStatus = "error"
			state.LastFetchErrorCode = code
			state.LastFetchMessage = diagnosis
		})
		application.logEvent("error", "Main", diagnosis)
		return "", err
	}
	if len(nodes) == 0 {
		return "", fmt.Errorf("VPNGate API 没有可用的 OpenVPN 节点")
	}
	application.enrichIPInfo(ctx, nodes)
	blacklist := application.loadBlacklist()
	application.mu.Lock()
	activeID := application.state.ActiveNodeID
	oldNodes := make(map[string]node, len(application.nodes))
	for _, old := range application.nodes {
		oldNodes[old.ID] = old
	}
	for index := range nodes {
		if !filepath.IsAbs(nodes[index].ConfigFile) {
			nodes[index].ConfigFile = filepath.Join(application.config.DataDir, nodes[index].ConfigFile)
		}
		nodes[index].Active = nodes[index].ID == activeID
		if old, ok := oldNodes[nodes[index].ID]; ok {
			nodes[index].ProbeStatus = old.ProbeStatus
			nodes[index].ProbeMessage = old.ProbeMessage
			nodes[index].ProbedAt = old.ProbedAt
			nodes[index].LatencyMS = old.LatencyMS
		}
	}
	nodes = sortNodes(nodes)
	application.nodes = nodes
	application.mu.Unlock()
	for index := range nodes {
		if err := os.WriteFile(nodes[index].ConfigFile, []byte(nodes[index].ConfigText), 0o600); err != nil {
			application.logEvent("warning", "Main", "写入节点配置失败: "+err.Error())
		}
	}
	if err := application.saveNodes(); err != nil {
		return "", err
	}
	message := fmt.Sprintf("已更新 %d 个 VPNGate OpenVPN 节点（%s）", len(nodes), fetchMessage)
	_ = application.updateState(func(state *runtimeState) {
		state.LastFetchAt = time.Now().Unix()
		state.LastFetchStatus = "ok"
		state.LastFetchMessage = message
		state.BlacklistedNodes = len(blacklist)
	})
	application.logEvent("info", "Main", message)
	return message, nil
}

func (application *store) fetchCandidates(ctx context.Context) ([]node, string, error) {
	type attempt struct {
		url      string
		insecure bool
	}
	attempts := []attempt{{url: application.config.APIURL}}
	if strings.HasPrefix(application.config.APIURL, "https://") {
		attempts = append(attempts,
			attempt{url: application.config.APIURL, insecure: true},
			attempt{url: "http://" + strings.TrimPrefix(application.config.APIURL, "https://")},
		)
	}
	blacklist := application.loadBlacklist()
	var lastError error
	for _, current := range attempts {
		nodes, err := application.fetchAttempt(ctx, current.url, current.insecure)
		if err != nil {
			lastError = err
			application.logEvent("warning", "Main", fmt.Sprintf("拉取失败 %s: %v", current.url, err))
			continue
		}
		filtered := nodes[:0]
		for _, candidate := range nodes {
			if _, blocked := blacklist[candidate.ID]; !blocked {
				filtered = append(filtered, candidate)
			}
		}
		if len(filtered) > 0 {
			mode := "HTTPS 校验"
			if current.insecure {
				mode = "HTTPS 兼容模式"
			} else if strings.HasPrefix(current.url, "http://") {
				mode = "HTTP 回退"
			}
			return filtered, mode, nil
		}
	}
	application.mu.RLock()
	cached := append([]node(nil), application.nodes...)
	application.mu.RUnlock()
	if len(cached) > 0 {
		return cached, "本地缓存", nil
	}
	return nil, "", fmt.Errorf("获取 VPNGate 节点失败: %w", lastError)
}

func (application *store) fetchAttempt(ctx context.Context, endpoint string, insecure bool) ([]node, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "gatepilot-go/1.0")
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
	if proxyURL, proxyErr := parseProxyURL(application.upstreamProxy()); proxyErr == nil && proxyURL != nil {
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
	return parseVPNGateCSV(response.Body, application.config.MaxScanRows)
}

func parseVPNGateCSV(source io.Reader, maximum int) ([]node, error) {
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
	result := make([]node, 0, maximum)
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

func nodeFromRecord(record []string, headings map[string]int) (node, bool) {
	value := func(name string) string {
		index, exists := headings[name]
		if !exists || index >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[index])
	}
	ip := value("IP")
	encoded := value("OpenVPN_ConfigData_Base64")
	if ip == "" || encoded == "" {
		return node{}, false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return node{}, false
	}
	configText := string(decoded)
	remoteHost, remotePort, protocol := parseRemote(configText, ip)
	country := value("CountryLong")
	if translated := countryTranslations[country]; translated != "" {
		country = translated
	}
	countryShort := value("CountryShort")
	id := safeName(strings.Join([]string{countryShort, ip, strconv.Itoa(remotePort), protocol}, "_"))
	configFile := filepath.Join("configs", id+".ovpn")
	return node{
		ID: id, Country: country, CountryShort: countryShort,
		HostName: value("HostName"), IP: ip,
		Score: parseInt64(value("Score")), Ping: parseInt64(value("Ping")),
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

func safeName(value string) string {
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

func (application *store) candidates() []node {
	ui, _, nodes := application.snapshot()
	blacklist := application.loadBlacklist()
	favorites := map[string]bool{}
	for _, id := range ui.FavoriteNodeIDs {
		favorites[id] = true
	}
	filtered := make([]node, 0, len(nodes))
	for _, candidate := range nodes {
		if _, blocked := blacklist[candidate.ID]; blocked && !candidate.Active {
			continue
		}
		if (ui.RoutingMode == "fixed_country" || ui.RoutingMode == "fixed_region") && ui.ForceCountry != "" && !countryMatches(candidate, ui.ForceCountry) {
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
		leftLatency, rightLatency := effectiveLatency(filtered[left]), effectiveLatency(filtered[right])
		if leftLatency != rightLatency {
			return leftLatency < rightLatency
		}
		return filtered[left].Score > filtered[right].Score
	})
	return filtered
}

func sortNodes(nodes []node) []node {
	result := append([]node(nil), nodes...)
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

func probeRank(candidate node) int {
	if candidate.Active || candidate.ProbeStatus == "available" {
		return 0
	}
	if candidate.ProbeStatus == "not_checked" || candidate.ProbeStatus == "testing" || candidate.ProbeStatus == "" {
		return 1
	}
	return 2
}

func effectiveLatency(candidate node) int64 {
	if candidate.LatencyMS > 0 {
		return candidate.LatencyMS
	}
	if candidate.Ping > 0 {
		return candidate.Ping
	}
	return 999999
}

func countryMatches(candidate node, target string) bool {
	target = strings.TrimSpace(strings.ToLower(target))
	return strings.ToLower(candidate.Country) == target || strings.ToLower(candidate.CountryShort) == target
}

func (application *store) toggleFavorite(id string) []string {
	application.mu.Lock()
	found := false
	result := make([]string, 0, len(application.ui.FavoriteNodeIDs)+1)
	for _, current := range application.ui.FavoriteNodeIDs {
		if current == id {
			found = true
			continue
		}
		result = append(result, current)
	}
	if !found {
		result = append(result, id)
	}
	application.ui.FavoriteNodeIDs = result
	application.mu.Unlock()
	_ = application.saveUI()
	return result
}
