package proxy

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RouteAction 表示分流决策。
type RouteAction int

const (
	RouteVPN    RouteAction = iota // 走 VPN 隧道
	RouteDirect                    // 直连，不经过 VPN
)

// RuleKind 标识规则匹配方式。
type RuleKind int

const (
	RuleDomain  RuleKind = iota // 域名后缀匹配
	RuleKeyword                 // 域名关键词包含
	RuleCIDR                    // IP/CIDR 匹配
)

// RouteRule 是一条分流规则。
type RouteRule struct {
	Kind    RuleKind    `json:"kind"`
	Value   string      `json:"value"`
	Action  RouteAction `json:"action"`
	domain  string
	keyword string
	cidr    netip.Prefix
}

// RoutingEngine 是线程安全的分流规则引擎。
type RoutingEngine struct {
	rules      atomic.Pointer[[]RouteRule]
	defaultAct RouteAction
}

var engine RoutingEngine

// InitRouting 初始化分流引擎。
func InitRouting(rules []RouteRule, defaultAction RouteAction) {
	parsed := parseRules(rules)
	engine.defaultAct = defaultAction
	engine.rules.Store(&parsed)
}

// UpdateRules 热更新分流规则。
func UpdateRules(rules []RouteRule, defaultAction RouteAction) {
	InitRouting(rules, defaultAction)
}

func parseRules(rules []RouteRule) []RouteRule {
	parsed := make([]RouteRule, 0, len(rules))
	for _, rule := range rules {
		rule.Value = strings.TrimSpace(rule.Value)
		if rule.Value == "" {
			continue
		}
		switch rule.Kind {
		case RuleDomain:
			rule.domain = strings.ToLower(strings.TrimPrefix(rule.Value, "."))
		case RuleKeyword:
			rule.keyword = strings.ToLower(rule.Value)
		case RuleCIDR:
			value := rule.Value
			if !strings.Contains(value, "/") {
				addr, err := netip.ParseAddr(value)
				if err != nil {
					continue
				}
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				rule.cidr = netip.PrefixFrom(addr, bits)
			} else {
				prefix, err := netip.ParsePrefix(value)
				if err != nil {
					continue
				}
				rule.cidr = prefix
			}
		default:
			continue
		}
		parsed = append(parsed, rule)
	}
	return parsed
}

// Route 根据目标主机决定走 VPN 还是直连。
func Route(host string) RouteAction {
	rules := engine.rules.Load()
	if rules == nil || len(*rules) == 0 {
		return engine.defaultAct
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip := net.ParseIP(host)
	for _, rule := range *rules {
		switch rule.Kind {
		case RuleDomain:
			if ip != nil {
				continue
			}
			if host == rule.domain || strings.HasSuffix(host, "."+rule.domain) {
				return rule.Action
			}
		case RuleKeyword:
			if ip != nil {
				continue
			}
			if strings.Contains(host, rule.keyword) {
				return rule.Action
			}
		case RuleCIDR:
			if ip == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			if rule.cidr.Contains(addr.Unmap()) {
				return rule.Action
			}
		}
	}
	return engine.defaultAct
}

// DefaultChinaDirectRules 返回内置的中国直连规则预设。
func DefaultChinaDirectRules() []RouteRule {
	domains := []string{
		"cn", "baidu.com", "qq.com", "taobao.com", "tmall.com", "jd.com",
		"alipay.com", "aliyun.com", "alicdn.com", "163.com", "126.com",
		"sina.com.cn", "weibo.com", "bilibili.com", "zhihu.com",
		"douyin.com", "bytedance.com", "ixigua.com",
		"meituan.com", "dianping.com", "xiaomi.com", "huawei.com",
		"honor.com", "oppo.com", "vivo.com", "lenovo.com",
		"csdn.net", "jianshu.com", "gitee.com", "oschina.net",
		"cnblogs.com", "segmentfault.com", "51cto.com",
		"iqiyi.com", "youku.com", "sohu.com", "ifeng.com",
		"huya.com", "douyu.com", "kuaishou.com",
		"cctv.com", "people.com.cn", "xinhuanet.com",
		"12306.cn", "ctrip.com", "qunar.com", "ele.me",
		"suning.com", "pinduoduo.com", "vip.com",
		"dingtalk.com", "feishu.cn", "wps.cn", "youdao.com",
		"netease.com", "tencent.com",
		"myqcloud.com", "qcloud.com", "gtimg.com",
		"amap.com", "autonavi.com",
	}
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"224.0.0.0/4", "0.0.0.0/8",
		"fc00::/7", "fe80::/10", "::1/128",
	}
	rules := make([]RouteRule, 0, len(domains)+len(cidrs))
	for _, domain := range domains {
		rules = append(rules, RouteRule{Kind: RuleDomain, Value: domain, Action: RouteDirect})
	}
	for _, cidr := range cidrs {
		rules = append(rules, RouteRule{Kind: RuleCIDR, Value: cidr, Action: RouteDirect})
	}
	return rules
}

var directDialerOnce sync.Once
var directNetDialer net.Dialer

// DialDirect 直连目标地址，不绑定 VPN 网卡。
func DialDirect(address string) (net.Conn, error) {
	directDialerOnce.Do(func() {
		directNetDialer = net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}
	})
	return directNetDialer.Dial("tcp", address)
}