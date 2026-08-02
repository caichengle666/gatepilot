package proxy

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	domainTypePlain      = 0
	domainTypeRegex      = 1
	domainTypeRootDomain = 2
	domainTypeFull       = 3
)

// GeoSiteMatcher 按分类匹配域名。
type GeoSiteMatcher struct {
	mu        sync.RWMutex
	domains   map[string]bool
	suffixes  []string
	suffixSet map[string]bool
	keywords  []string
	keywordAC *ahoCorasick
	regexps   []*regexp.Regexp
}

type ahoCorasick struct {
	gotoFn map[int]map[byte]int
	fail   []int
	output [][]int
}

func buildAhoCorasick(patterns []string) *ahoCorasick {
	if len(patterns) == 0 {
		return nil
	}
	ac := &ahoCorasick{
		gotoFn: make(map[int]map[byte]int),
		fail:   []int{0},
		output: [][]int{nil},
	}
	for _, p := range patterns {
		if len(p) == 0 {
			continue
		}
		cur := 0
		for j := 0; j < len(p); j++ {
			c := p[j]
			if _, ok := ac.gotoFn[cur]; !ok {
				ac.gotoFn[cur] = make(map[byte]int)
			}
			nxt, ok := ac.gotoFn[cur][c]
			if !ok {
				nxt = len(ac.fail)
				ac.gotoFn[cur][c] = nxt
				ac.fail = append(ac.fail, 0)
				ac.output = append(ac.output, nil)
				cur = nxt
			} else {
				cur = nxt
			}
		}
		if len(ac.output[cur]) == 0 {
			ac.output[cur] = []int{1}
		} else {
			ac.output[cur] = append(ac.output[cur], 1)
		}
	}
	queue := []int{}
	for _, child := range ac.gotoFn[0] {
		queue = append(queue, child)
		ac.fail[child] = 0
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		for c, u := range ac.gotoFn[r] {
			queue = append(queue, u)
			f := ac.fail[r]
			for {
				if nxt, ok := ac.gotoFn[f][c]; ok && nxt != u {
					f = nxt
					break
				}
				if f == 0 {
					break
				}
				f = ac.fail[f]
			}
			if nxt, ok := ac.gotoFn[f][c]; ok && nxt != u {
				ac.fail[u] = nxt
			} else {
				ac.fail[u] = 0
			}
			ac.output[u] = append(ac.output[u], ac.output[ac.fail[u]]...)
		}
	}
	return ac
}

func (ac *ahoCorasick) contains(text string) bool {
	if ac == nil {
		return false
	}
	cur := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		for {
			if nxt, ok := ac.gotoFn[cur][c]; ok {
				cur = nxt
				break
			}
			if cur == 0 {
				break
			}
			cur = ac.fail[cur]
		}
		if len(ac.output[cur]) > 0 {
			return true
		}
	}
	return false
}

var (
	geoSiteMatchers   = map[string]*GeoSiteMatcher{}
	geoSiteMatchersMu sync.RWMutex
	geoSiteDataPath   string
)

// SetGeoSitePath 设置 geosite.dat 文件路径。
func SetGeoSitePath(path string) { geoSiteDataPath = path }

func getGeoSiteMatcher(category string) *GeoSiteMatcher {
	cat := strings.ToLower(category)
	geoSiteMatchersMu.RLock()
	if m, ok := geoSiteMatchers[cat]; ok {
		geoSiteMatchersMu.RUnlock()
		return m
	}
	geoSiteMatchersMu.RUnlock()

	data, err := os.ReadFile(geoSiteDataPath)
	if err != nil {
		return nil
	}
	m, err := parseGeoSiteByScan(data, cat)
	if err != nil {
		return nil
	}
	m.keywordAC = buildAhoCorasick(m.keywords)
	geoSiteMatchersMu.Lock()
	geoSiteMatchers[cat] = m
	geoSiteMatchersMu.Unlock()
	return m
}

func parseGeoSiteByScan(data []byte, category string) (*GeoSiteMatcher, error) {
	code := strings.ToUpper(category)
	codeB := []byte(code)
	codeLen := len(codeB)
	if codeLen == 0 {
		return nil, fmt.Errorf("empty category")
	}
	need := 2 + codeLen

	m := &GeoSiteMatcher{domains: make(map[string]bool), suffixSet: make(map[string]bool)}
	offset := 0
	for offset < len(data) {
		_, wtype, n := protowire.ConsumeTag(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		if wtype != protowire.BytesType {
			n := protowire.ConsumeFieldValue(1, wtype, data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			continue
		}
		bodyLen, n := protowire.ConsumeVarint(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		bodyStart := offset
		offset += int(bodyLen)
		if offset > len(data) {
			break
		}
		body := data[bodyStart : bodyStart+int(bodyLen)]
		if len(body) >= need && body[0] == 0x0a && int(body[1]) == codeLen && bytes.Equal(body[2:need], codeB) {
			m.parseGeoSiteDomains(body)
		}
	}
	return m, nil
}

func (m *GeoSiteMatcher) parseGeoSiteDomains(data []byte) {
	offset := 0
	for offset < len(data) {
		num, wtype, n := protowire.ConsumeTag(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		if wtype == protowire.BytesType && num == 2 {
			val, n := protowire.ConsumeBytes(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			m.parseOneDomain(val)
		} else {
			n := protowire.ConsumeFieldValue(num, wtype, data[offset:])
			if n <= 0 {
				break
			}
			offset += n
		}
	}
}

func (m *GeoSiteMatcher) parseOneDomain(data []byte) {
	var value string
	kind := domainTypePlain
	offset := 0
	for offset < len(data) {
		num, wtype, n := protowire.ConsumeTag(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		switch {
		case wtype == protowire.VarintType && num == 1:
			val, n := protowire.ConsumeVarint(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			kind = int(val)
		case wtype == protowire.BytesType && num == 2:
			val, n := protowire.ConsumeBytes(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			value = strings.ToLower(string(val))
		default:
			n := protowire.ConsumeFieldValue(num, wtype, data[offset:])
			if n <= 0 {
				break
			}
			offset += n
		}
	}
	if value == "" {
		return
	}
	switch kind {
	case domainTypeFull:
		m.domains[value] = true
	case domainTypeRootDomain:
		sv := strings.TrimPrefix(value, ".")
		m.suffixes = append(m.suffixes, sv)
		m.suffixSet[sv] = true
	case domainTypeRegex:
		re, err := regexp.Compile(value)
		if err == nil {
			m.regexps = append(m.regexps, re)
		}
	default:
		m.keywords = append(m.keywords, value)
	}
}

// Match 判断域名是否属于该分类。
func (m *GeoSiteMatcher) Match(domain string) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	domain = strings.ToLower(domain)
	if m.domains[domain] {
		return true
	}
	d := domain
	for {
		if m.suffixSet[d] {
			return true
		}
		dot := strings.IndexByte(d, '.')
		if dot < 0 || dot >= len(d)-1 {
			break
		}
		d = d[dot+1:]
	}
	if m.keywordAC != nil {
		if m.keywordAC.contains(domain) {
			return true
		}
	} else {
		for _, k := range m.keywords {
			if strings.Contains(domain, k) {
				return true
			}
		}
	}
	for _, re := range m.regexps {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

// LoadGeoSite 加载 geosite.dat 并记录域名数量。
func LoadGeoSite() int {
	data, err := os.ReadFile(geoSiteDataPath)
	if err != nil {
		log.Printf("[Geo] geosite: cannot read %s: %v", geoSiteDataPath, err)
		return 0
	}
	m, err := parseGeoSiteByScan(data, "CN")
	if err != nil {
		log.Printf("[Geo] geosite: parse error: %v", err)
		return 0
	}
	m.keywordAC = buildAhoCorasick(m.keywords)
	geoSiteMatchersMu.Lock()
	geoSiteMatchers = map[string]*GeoSiteMatcher{"cn": m}
	geoSiteMatchersMu.Unlock()
	total := len(m.suffixes) + len(m.domains) + len(m.keywords) + len(m.regexps)
	log.Printf("[Geo] geosite loaded (%d suffixes, %d domains, %d keywords, %d regexps) from %s",
		len(m.suffixes), len(m.domains), len(m.keywords), len(m.regexps), geoSiteDataPath)
	return total
}

// ResetGeoSiteCache 清空分类缓存（升级后调用）。
func ResetGeoSiteCache() {
	geoSiteMatchersMu.Lock()
	geoSiteMatchers = map[string]*GeoSiteMatcher{}
	geoSiteMatchersMu.Unlock()
}