package web

import "testing"

func TestValidDNSLeakTestID(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "x82asz47xtcbias3", want: true},
		{value: "12345678", want: true},
		{value: "short", want: false},
		{value: "invalid.example", want: false},
		{value: "../invalid", want: false},
	} {
		if got := validDNSLeakTestID(test.value); got != test.want {
			t.Fatalf("validDNSLeakTestID(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestAnalyzeDNSLeak(t *testing.T) {
	tests := []struct {
		name      string
		entries   []dnsLeakResult
		available bool
		leaked    bool
	}{
		{
			name: "same exit network",
			entries: []dnsLeakResult{
				{IP: "203.0.113.1", ASN: "AS64500", Type: "ip"},
				{IP: "203.0.113.53", CountryName: "Japan", ASN: "AS64500", Type: "dns"},
			},
			available: true,
			leaked:    false,
		},
		{
			name: "different resolver network",
			entries: []dnsLeakResult{
				{IP: "203.0.113.1", ASN: "AS64500", Type: "ip"},
				{IP: "198.51.100.53", CountryName: "China", ASN: "AS64501", Type: "dns"},
			},
			available: true,
			leaked:    true,
		},
		{
			name: "missing asn",
			entries: []dnsLeakResult{
				{IP: "203.0.113.1", Type: "ip"},
				{IP: "198.51.100.53", Type: "dns"},
			},
			available: false,
			leaked:    false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := analyzeDNSLeak(test.entries)
			if result["available"] != test.available || result["leaked"] != test.leaked {
				t.Fatalf("analyzeDNSLeak() = %+v, want available=%v leaked=%v", result, test.available, test.leaked)
			}
		})
	}
}
