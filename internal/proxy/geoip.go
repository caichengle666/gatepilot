package proxy

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
)

// GeoIPMatcher 按国家匹配 IP 段。
type GeoIPMatcher struct {
	mu    sync.RWMutex
	cidrs []netip.Prefix
}

var (
	geoIPMatchers   = map[string]*GeoIPMatcher{}
	geoIPMatchersMu sync.RWMutex
	geoIPDataPath   string
)

// SetGeoIPPath 设置 geoip.dat 文件路径。
func SetGeoIPPath(path string) { geoIPDataPath = path }

func getGeoIPMatcher(country string) *GeoIPMatcher {
	c := strings.ToLower(country)
	geoIPMatchersMu.RLock()
	if m, ok := geoIPMatchers[c]; ok {
		geoIPMatchersMu.RUnlock()
		return m
	}
	geoIPMatchersMu.RUnlock()

	data, err := os.ReadFile(geoIPDataPath)
	if err != nil {
		return nil
	}
	m, err := newGeoIPMatcher(data, []string{c})
	if err != nil {
		return nil
	}
	geoIPMatchersMu.Lock()
	geoIPMatchers[c] = m
	geoIPMatchersMu.Unlock()
	return m
}

func newGeoIPMatcher(data []byte, countries []string) (*GeoIPMatcher, error) {
	want := make(map[string]bool, len(countries))
	for _, c := range countries {
		want[strings.ToLower(c)] = true
	}
	m := &GeoIPMatcher{}
	for offset := 0; offset < len(data); {
		num, wtype, n := protowire.ConsumeTag(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		if wtype == protowire.BytesType {
			val, n := protowire.ConsumeBytes(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			if num == 1 {
				m.parseEntry(val, want)
			}
		} else {
			n := protowire.ConsumeFieldValue(num, wtype, data[offset:])
			if n <= 0 {
				break
			}
			offset += n
		}
	}
	sort.Slice(m.cidrs, func(i, j int) bool {
		return m.cidrs[i].Addr().Less(m.cidrs[j].Addr())
	})
	return m, nil
}

func (m *GeoIPMatcher) parseEntry(data []byte, want map[string]bool) {
	var country string
	var cidrs []netip.Prefix
	for offset := 0; offset < len(data); {
		num, wtype, n := protowire.ConsumeTag(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		switch wtype {
		case protowire.BytesType:
			val, n := protowire.ConsumeBytes(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			if num == 1 {
				country = strings.ToLower(string(val))
			} else if num == 2 {
				if c, err := parseGeoCIDR(val); err == nil {
					cidrs = append(cidrs, c)
				}
			}
		default:
			n := protowire.ConsumeFieldValue(num, wtype, data[offset:])
			if n <= 0 {
				break
			}
			offset += n
		}
	}
	if country != "" && want[country] {
		m.cidrs = append(m.cidrs, cidrs...)
	}
}

func parseGeoCIDR(data []byte) (netip.Prefix, error) {
	var ipBytes []byte
	var prefixBits int
	for offset := 0; offset < len(data); {
		num, wtype, n := protowire.ConsumeTag(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		switch wtype {
		case protowire.BytesType:
			val, n := protowire.ConsumeBytes(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			if num == 1 {
				ipBytes = val
			}
		case protowire.VarintType:
			val, n := protowire.ConsumeVarint(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			if num == 2 {
				prefixBits = int(val)
			}
		default:
			n := protowire.ConsumeFieldValue(num, wtype, data[offset:])
			if n <= 0 {
				break
			}
			offset += n
		}
	}
	if len(ipBytes) == 0 {
		return netip.Prefix{}, fmt.Errorf("empty IP")
	}
	addr, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("bad IP: %v", ipBytes)
	}
	return addr.Prefix(prefixBits)
}

// Contains 用二分查找判断 IP 是否属于该国家。
func (m *GeoIPMatcher) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.cidrs) == 0 {
		return false
	}
	idx := sort.Search(len(m.cidrs), func(i int) bool {
		return ip.Less(m.cidrs[i].Addr())
	})
	maxScan := 8
	for i := idx - 1; i >= 0 && maxScan > 0; i-- {
		maxScan--
		if m.cidrs[i].Contains(ip) {
			return true
		}
	}
	if idx < len(m.cidrs) && m.cidrs[idx].Contains(ip) {
		return true
	}
	return false
}

// LoadGeoIP 加载 geoip.dat 并记录 CIDR 数量。
func LoadGeoIP() int {
	data, err := os.ReadFile(geoIPDataPath)
	if err != nil {
		log.Printf("[Geo] geoip: cannot read %s: %v", geoIPDataPath, err)
		return 0
	}
	m, err := newGeoIPMatcher(data, []string{"cn"})
	if err != nil {
		log.Printf("[Geo] geoip: parse error: %v", err)
		return 0
	}
	geoIPMatchersMu.Lock()
	geoIPMatchers = map[string]*GeoIPMatcher{"cn": m}
	geoIPMatchersMu.Unlock()
	log.Printf("[Geo] geoip loaded (%d CIDR) from %s", len(m.cidrs), geoIPDataPath)
	return len(m.cidrs)
}

// ResetGeoIPCache 清空国家缓存（升级后调用）。
func ResetGeoIPCache() {
	geoIPMatchersMu.Lock()
	geoIPMatchers = map[string]*GeoIPMatcher{}
	geoIPMatchersMu.Unlock()
}