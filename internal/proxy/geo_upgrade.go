package proxy

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caichengle666/gatepilot/internal/store"
)

var (
	geoUpstreamProxy string
	geoDownloadOnce  sync.Once
	geoStateMu       sync.Mutex
	geoState         = map[string]string{}
)

// SetGeoUpstreamProxy 设置 geo 文件下载使用的前置代理（留空表示直连）。
func SetGeoUpstreamProxy(raw string) {
	geoUpstreamProxy = strings.TrimSpace(raw)
}

func setGeoState(kind, state string) {
	geoStateMu.Lock()
	geoState[kind] = state
	geoStateMu.Unlock()
}

func getGeoState(kind string) string {
	geoStateMu.Lock()
	defer geoStateMu.Unlock()
	return geoState[kind]
}

var geoUpgradeMirrors = map[string][]string{
	"geoip": {
		"https://ghfast.top/https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
		"https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
	},
	"geosite": {
		"https://ghfast.top/https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
		"https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
	},
}

// GeoStatus 返回 geo 数据文件状态。
// GeoStatus 返回 geo 数据文件状态：value 为 {"status","detail"}。
func GeoStatus() map[string]map[string]string {
	result := map[string]map[string]string{}
	for _, kind := range []string{"geoip", "geosite"} {
		path := GeoFilePath(kind)
		info, err := os.Stat(path)
		hasFile := err == nil && info.Size() >= 1000
		entry := map[string]string{}
		switch {
		case getGeoState(kind) == "downloading":
			entry["status"] = "downloading"
			entry["detail"] = "数据文件下载中..."
		case !hasFile && getGeoState(kind) == "failed":
			entry["status"] = "failed"
			entry["detail"] = "数据文件下载失败；请检查网络或前置代理后点击「在线升级」重试"
		case !hasFile:
			entry["status"] = "missing"
			entry["detail"] = "未加载（本地缺少数据文件）"
		default:
			entry["status"] = "ready"
			if kind == "geoip" {
				m := getGeoIPMatcher("cn")
				if m != nil {
					m.mu.RLock()
					entry["detail"] = fmt.Sprintf("已加载 %d 个网段", len(m.cidrs))
					m.mu.RUnlock()
				} else {
					entry["detail"] = fmt.Sprintf("已加载 %d KB", info.Size()/1024)
				}
			} else {
				m := getGeoSiteMatcher("cn")
				if m != nil {
					m.mu.RLock()
					entry["detail"] = fmt.Sprintf("已加载 %d 个域名", len(m.suffixes)+len(m.domains)+len(m.keywords)+len(m.regexps))
					m.mu.RUnlock()
				} else {
					entry["detail"] = fmt.Sprintf("已加载 %d KB", info.Size()/1024)
				}
			}
		}
		result[kind] = entry
	}
	return result
}

// GeoFilePath 返回 geo 数据文件的完整路径。
func GeoFilePath(kind string) string {
	executable, _ := os.Executable()
	dir := filepath.Dir(executable)
	return filepath.Join(dir, kind+".dat")
}

// EnsureGeoFiles 启动时检查 geo 文件，缺失则自动下载。
func EnsureGeoFiles() {
	SetGeoIPPath(GeoFilePath("geoip"))
	SetGeoSitePath(GeoFilePath("geosite"))
	LoadGeoIP()
	LoadGeoSite()
	geoDownloadOnce.Do(func() {
		missing := make([]string, 0, 2)
		for _, kind := range []string{"geoip", "geosite"} {
			path := GeoFilePath(kind)
			if info, err := os.Stat(path); err == nil && info.Size() >= 1000 {
				continue
			}
			missing = append(missing, kind)
		}
		if len(missing) == 0 {
			return
		}
		go func() {
			for _, kind := range missing {
				path := GeoFilePath(kind)
				log.Printf("[Geo] 本地缺少 %s.dat，后台自动下载中...", kind)
				setGeoState(kind, "downloading")
				ok := false
				for _, url := range geoUpgradeMirrors[kind] {
					if err := downloadGeoFile(url, path); err != nil {
						log.Printf("[Geo] 自动下载失败 %s: %v", url, err)
						continue
					}
					log.Printf("[Geo] 自动下载完成: %s", path)
					ok = true
					break
				}
				if !ok {
					setGeoState(kind, "failed")
					log.Printf("[Geo] 自动下载失败，分流规则中 geosite/geoip 将不可用: %s", path)
					continue
				}
				setGeoState(kind, "")
				if kind == "geoip" {
					LoadGeoIP()
				} else {
					LoadGeoSite()
				}
			}
		}()
	})
}

// UpgradeGeoFiles 在线升级 geoip.dat 和 geosite.dat。
func UpgradeGeoFiles() map[string]string {
	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for kind, mirrors := range geoUpgradeMirrors {
		wg.Add(1)
		go func(k string, ms []string) {
			defer wg.Done()
			path := GeoFilePath(k)
			setGeoState(k, "downloading")
			for _, url := range ms {
				if err := downloadGeoFile(url, path); err == nil {
					setGeoState(k, "")
					mu.Lock()
					results[k] = "updated"
					mu.Unlock()
					return
				}
			}
			setGeoState(k, "failed")
			mu.Lock()
			results[k] = "all mirrors failed"
			mu.Unlock()
		}(kind, mirrors)
	}
	wg.Wait()
	allOK := true
	for _, v := range results {
		if v != "updated" {
			allOK = false
		}
	}
	if allOK {
		ResetGeoIPCache()
		ResetGeoSiteCache()
		LoadGeoIP()
		LoadGeoSite()
		log.Printf("[Geo] upgraded and reloaded")
	}
	return results
}

func downloadGeoFile(url, path string) error {
	client := newGeoHTTPClient()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "gatepilot-go/1.0")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	tmpName := path + ".tmp"
	file, err := os.Create(tmpName)
	if err != nil {
		return err
	}
	defer file.Close()
	n, err := io.Copy(file, response.Body)
	if err != nil {
		os.Remove(tmpName)
		return err
	}
	if n < 1000 {
		os.Remove(tmpName)
		return fmt.Errorf("file too small (%d bytes)", n)
	}
	file.Close()
	return os.Rename(tmpName, path)
}

// newGeoHTTPClient 构造 geo 下载客户端：总超时 60 秒，并优先使用配置的前置代理。
func newGeoHTTPClient() *http.Client {
	client := &http.Client{Timeout: 60 * time.Second}
	if geoUpstreamProxy == "" {
		return client
	}
	proxyURL, err := store.ParseProxyURL(geoUpstreamProxy)
	if err != nil || proxyURL == nil {
		return client
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client.Transport = transport
	return client
}

// ReloadGeoData 重新加载 geo 数据文件。
func ReloadGeoData() {
	ResetGeoIPCache()
	ResetGeoSiteCache()
	LoadGeoIP()
	LoadGeoSite()
}

// GeoIPMatcherCIDRCount 返回已加载的 geoip CIDR 数量（用于状态显示）。
func GeoIPMatcherCIDRCount() int {
	m := getGeoIPMatcher("cn")
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cidrs)
}

// GeoSiteMatcherDomainCount 返回已加载的 geosite 域名数量。
func GeoSiteMatcherDomainCount() int {
	m := getGeoSiteMatcher("cn")
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.suffixes) + len(m.domains) + len(m.keywords) + len(m.regexps)
}

// SplitRuleKindToString 将 RuleKind 转为字符串。
func SplitRuleKindToString(kind RuleKind) string {
	switch kind {
	case RuleDomain:
		return "domain"
	case RuleKeyword:
		return "keyword"
	case RuleCIDR:
		return "cidr"
	case RuleGeoSite:
		return "geosite"
	case RuleGeoIP:
		return "geoip"
	default:
		return "unknown"
	}
}

// StringToRuleKind 将字符串转为 RuleKind。
func StringToRuleKind(s string) (RuleKind, bool) {
	switch strings.ToLower(s) {
	case "domain":
		return RuleDomain, true
	case "keyword":
		return RuleKeyword, true
	case "cidr":
		return RuleCIDR, true
	case "geosite":
		return RuleGeoSite, true
	case "geoip":
		return RuleGeoIP, true
	default:
		return RuleDomain, false
	}
}
