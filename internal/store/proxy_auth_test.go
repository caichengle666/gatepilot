package store

import "testing"

func TestProxyHostIsLocal(t *testing.T) {
	for _, host := range []string{"", "127.0.0.1", "localhost", "::1", "[::1]"} {
		if !ProxyHostIsLocal(host) {
			t.Fatalf("host %q should be local", host)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "192.168.2.11"} {
		if ProxyHostIsLocal(host) {
			t.Fatalf("host %q should not be local", host)
		}
	}
}

func TestValidateProxyAuthRequiresCredentialsForExternalHost(t *testing.T) {
	t.Setenv("LOCAL_PROXY_PUBLISHED_HOST", "")
	if err := ValidateProxyAuth("0.0.0.0", UIConfig{}); err == nil {
		t.Fatal("external proxy host without auth should be rejected")
	}
	if err := ValidateProxyAuth("0.0.0.0", UIConfig{ProxyAuthEnabled: true, ProxyUsername: "user"}); err == nil {
		t.Fatal("external proxy host with empty password should be rejected")
	}
	if err := ValidateProxyAuth("0.0.0.0", UIConfig{ProxyAuthEnabled: true, ProxyUsername: "user", ProxyPassword: "pass"}); err != nil {
		t.Fatalf("external proxy host with auth should be accepted: %v", err)
	}
}

func TestValidateProxyAuthAllowsLocalWithoutAuth(t *testing.T) {
	if err := ValidateProxyAuth("127.0.0.1", UIConfig{}); err != nil {
		t.Fatalf("local proxy host without auth should be accepted: %v", err)
	}
}

func TestValidateProxyAuthAllowsContainerBindPublishedLocally(t *testing.T) {
	t.Setenv("LOCAL_PROXY_PUBLISHED_HOST", "127.0.0.1")
	if err := ValidateProxyAuth("0.0.0.0", UIConfig{}); err != nil {
		t.Fatalf("container proxy published only on localhost should be accepted: %v", err)
	}
	t.Setenv("LOCAL_PROXY_PUBLISHED_HOST", "0.0.0.0")
	if err := ValidateProxyAuth("0.0.0.0", UIConfig{}); err == nil {
		t.Fatal("publicly published container proxy without auth should be rejected")
	}
}
