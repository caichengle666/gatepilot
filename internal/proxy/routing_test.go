package proxy

import (
	"testing"
	"time"
)

func TestRouteDomainSuffix(t *testing.T) {
	rules := []RouteRule{
		{Kind: RuleDomain, Value: "baidu.com", Action: RouteDirect},
		{Kind: RuleDomain, Value: "google.com", Action: RouteVPN},
	}
	InitRouting(rules, RouteVPN)
	defer InitRouting(nil, RouteVPN)

	tests := []struct {
		host string
		want RouteAction
	}{
		{"baidu.com", RouteDirect},
		{"www.baidu.com", RouteDirect},
		{"tieba.baidu.com", RouteDirect},
		{"google.com", RouteVPN},
		{"www.google.com", RouteVPN},
		{"example.com", RouteVPN},
		{"notbaidu.com", RouteVPN},
	}
	for _, test := range tests {
		if got := Route(test.host); got != test.want {
			t.Errorf("Route(%q) = %d, want %d", test.host, got, test.want)
		}
	}
}

func TestRouteKeyword(t *testing.T) {
	rules := []RouteRule{
		{Kind: RuleKeyword, Value: "ali", Action: RouteDirect},
	}
	InitRouting(rules, RouteVPN)
	defer InitRouting(nil, RouteVPN)

	if Route("alicdn.com") != RouteDirect {
		t.Error("keyword ali should match alicdn.com")
	}
	if Route("alipay.com") != RouteDirect {
		t.Error("keyword ali should match alipay.com")
	}
	if Route("example.com") != RouteVPN {
		t.Error("keyword ali should not match example.com")
	}
}

func TestRouteCIDR(t *testing.T) {
	rules := []RouteRule{
		{Kind: RuleCIDR, Value: "192.168.0.0/16", Action: RouteDirect},
		{Kind: RuleCIDR, Value: "10.0.0.1", Action: RouteDirect},
	}
	InitRouting(rules, RouteVPN)
	defer InitRouting(nil, RouteVPN)

	tests := []struct {
		host string
		want RouteAction
	}{
		{"192.168.1.100", RouteDirect},
		{"192.168.255.255", RouteDirect},
		{"10.0.0.1", RouteDirect},
		{"10.0.0.2", RouteVPN},
		{"8.8.8.8", RouteVPN},
		{"baidu.com", RouteVPN},
	}
	for _, test := range tests {
		if got := Route(test.host); got != test.want {
			t.Errorf("Route(%q) = %d, want %d", test.host, got, test.want)
		}
	}
}

func TestRouteDefaultAction(t *testing.T) {
	rules := []RouteRule{
		{Kind: RuleDomain, Value: "cn", Action: RouteDirect},
	}
	InitRouting(rules, RouteDirect)
	defer InitRouting(nil, RouteVPN)

	if Route("example.com") != RouteDirect {
		t.Error("default action should be direct")
	}
}

func TestRouteEmptyRules(t *testing.T) {
	InitRouting(nil, RouteVPN)
	if Route("anything.com") != RouteVPN {
		t.Error("empty rules should return default VPN")
	}
}

func TestDefaultChinaDirectRules(t *testing.T) {
	rules := DefaultChinaDirectRules()
	if len(rules) == 0 {
		t.Fatal("expected non-empty preset rules")
	}
	InitRouting(rules, RouteVPN)
	defer InitRouting(nil, RouteVPN)

	if Route("www.baidu.com") != RouteDirect {
		t.Error("baidu.com should be direct in China presets")
	}
	if Route("192.168.1.1") != RouteDirect {
		t.Error("private IP should be direct in China presets")
	}
	if Route("www.google.com") != RouteVPN {
		t.Error("google.com should go through VPN")
	}
}

func TestFailoverTracker(t *testing.T) {
	triggered := make(chan int, 1)
	tracker := NewFailoverTracker(3, time.Millisecond, func(failures int) {
		triggered <- failures
	})

	tracker.RecordFailure()
	tracker.RecordFailure()
	if tracker.Consecutive() != 2 {
		t.Fatalf("consecutive = %d, want 2", tracker.Consecutive())
	}
	tracker.RecordSuccess()
	if tracker.Consecutive() != 0 {
		t.Fatal("success should reset consecutive")
	}

	tracker.RecordFailure()
	tracker.RecordFailure()
	tracker.RecordFailure()

	select {
	case <-triggered:
	case <-time.After(time.Second):
		t.Fatal("failover should have triggered after 3 failures")
	}

	failures, successes := tracker.Stats()
	if failures != 5 || successes != 1 {
		t.Fatalf("stats = %d/%d, want 5/1", failures, successes)
	}
}