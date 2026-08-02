package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/caichengle666/gatepilot/internal/store"
	"github.com/caichengle666/gatepilot/internal/vpn"
)

func newProxyAuthTestServer(t *testing.T) (*Application, *store.Store) {
	t.Helper()
	config := store.AppConfig{DataDir: t.TempDir(), ProxyHost: "127.0.0.1", ProxyPort: 7928, UIPort: 8787, TargetValidNodes: 1, ManualTestNodeLimit: 1, InitialTestLimit: 1}
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApplication(application, vpn.NewController(application))
	return app, application
}

func loginProxyAuthTestServer(t *testing.T, serverURL string, application *store.Store) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	ui, _, _ := application.Snapshot()
	body, _ := json.Marshal(map[string]string{"username": ui.Username, "password": ui.Password})
	response, err := client.Post(serverURL+"/"+ui.SecretPath+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %s", response.Status)
	}
	return client
}

func TestUpdateSettingsSavesProxyAuth(t *testing.T) {
	app, application := newProxyAuthTestServer(t)
	server := httptest.NewServer(app)
	defer server.Close()
	client := loginProxyAuthTestServer(t, server.URL, application)
	ui, _, _ := application.Snapshot()
	payload, _ := json.Marshal(map[string]any{"proxy_auth_enabled": true, "proxy_username": "proxy-user", "proxy_password": "proxy-pass"})
	response, err := client.Post(server.URL+"/"+ui.SecretPath+"/api/update_settings", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("update settings failed: %s", response.Status)
	}
	updated, _, _ := application.Snapshot()
	if !updated.ProxyAuthEnabled || updated.ProxyUsername != "proxy-user" || updated.ProxyPassword != "proxy-pass" {
		t.Fatalf("proxy auth was not saved: %+v", updated)
	}
	username, password, enabled := store.ProxyCredentials(updated)
	if !enabled || username != "proxy-user" || password != "proxy-pass" {
		t.Fatalf("effective proxy credentials = %q/%q enabled=%v", username, password, enabled)
	}
}

func TestUpdateSettingsRejectsExternalHostWithoutProxyAuth(t *testing.T) {
	app, application := newProxyAuthTestServer(t)
	app.Store.Config.ProxyHost = "0.0.0.0"
	server := httptest.NewServer(app)
	defer server.Close()
	client := loginProxyAuthTestServer(t, server.URL, application)
	ui, _, _ := application.Snapshot()
	payload, _ := json.Marshal(map[string]any{"proxy_auth_enabled": false})
	response, err := client.Post(server.URL+"/"+ui.SecretPath+"/api/update_settings", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %s", response.Status)
	}
}
