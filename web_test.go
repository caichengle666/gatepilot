package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebLoginAndAPIs(t *testing.T) {
	config := loadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	application, err := newStore(config)
	if err != nil {
		t.Fatal(err)
	}
	application.mu.Lock()
	application.ui.SecretPath = "testsecret"
	application.ui.Username = "test-user"
	application.ui.Password = "test-password"
	application.nodes = []node{{ID: "JP_test", Country: "日本", CountryShort: "JP", ConfigText: "client\nremote 127.0.0.1 1194\n"}}
	application.mu.Unlock()
	web := newWebApplication(application, newVPNController(application))
	server := httptest.NewServer(web)
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"username": "test-user", "password": "test-password"})
	response, err := client.Post(server.URL+"/testsecret/api/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login returned %s", response.Status)
	}
	response, err = client.Get(server.URL + "/testsecret/api/nodes")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Nodes []node       `json:"nodes"`
		State runtimeState `json:"state"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(payload.Nodes) != 1 || payload.State.Status != "disconnected" {
		t.Fatalf("unexpected API response: status=%s payload=%+v", response.Status, payload)
	}
	if payload.Nodes[0].ConfigText != "" {
		t.Fatal("nodes API exposed OpenVPN configuration")
	}

	response, err = client.Get(server.URL + "/testsecret/")
	if err != nil {
		t.Fatal(err)
	}
	page, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(page), "GatePilot 节点池管理系统") {
		t.Fatalf("unexpected management page: status=%s", response.Status)
	}

	response, err = client.Get(server.URL + "/testsecret/api/gateway_status")
	if err != nil {
		t.Fatal(err)
	}
	var gateway struct {
		OK       bool  `json:"ok"`
		Services []any `json:"services"`
	}
	if err := json.NewDecoder(response.Body).Decode(&gateway); err != nil {
		_ = response.Body.Close()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !gateway.OK || len(gateway.Services) != 6 {
		t.Fatalf("unexpected gateway response: status=%s payload=%+v", response.Status, gateway)
	}

	response, err = client.Get(server.URL + "/testsecret/configs/JP_test.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(profile) != "client\nremote 127.0.0.1 1194\n" {
		t.Fatalf("unexpected config download: status=%s body=%q", response.Status, profile)
	}
}

func TestCredentialUpdateKeepsServerAvailable(t *testing.T) {
	config := loadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	application, err := newStore(config)
	if err != nil {
		t.Fatal(err)
	}
	application.mu.Lock()
	application.ui.SecretPath = "testsecret"
	application.ui.Username = "test-user"
	application.ui.Password = "old-password"
	application.mu.Unlock()
	server := httptest.NewServer(newWebApplication(application, newVPNController(application)))
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"username": "test-user", "password": "old-password"})
	response, err := client.Post(server.URL+"/testsecret/api/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	updateBody, _ := json.Marshal(map[string]any{
		"username": "test-user", "password": "new-password", "port": application.ui.Port, "secret_path": "testsecret",
	})
	response, err = client.Post(server.URL+"/testsecret/api/update_credentials", "application/json", bytes.NewReader(updateBody))
	if err != nil {
		t.Fatal(err)
	}
	var updateResult struct {
		OK             bool   `json:"ok"`
		RestartNeeded  bool   `json:"restart_needed"`
		ReauthRequired bool   `json:"reauth_required"`
		Error          string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&updateResult); err != nil {
		_ = response.Body.Close()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !updateResult.OK || updateResult.RestartNeeded || !updateResult.ReauthRequired {
		t.Fatalf("unexpected credential update response: status=%s payload=%+v", response.Status, updateResult)
	}
	loginBody, _ = json.Marshal(map[string]string{"username": "test-user", "password": "new-password"})
	response, err = client.Post(server.URL+"/testsecret/api/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("new credentials login returned %s", response.Status)
	}
}

func TestUpdateSettingsPersistsProxyAndSpeedSettings(t *testing.T) {
	config := loadAppConfig()
	config.DataDir = t.TempDir()
	application, err := newStore(config)
	if err != nil {
		t.Fatal(err)
	}
	web := newWebApplication(application, newVPNController(application))
	body, _ := json.Marshal(map[string]any{
		"upstream_proxy": "127.0.0.1:7890",
		"speed_test_url": "https://speed.example/test.bin",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/update_settings", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	web.updateSettings(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update returned %d: %s", recorder.Code, recorder.Body.String())
	}
	ui, _, _ := application.snapshot()
	if ui.UpstreamProxy != "http://127.0.0.1:7890" {
		t.Fatalf("upstream proxy = %q", ui.UpstreamProxy)
	}
	if ui.SpeedTestURL != "https://speed.example/test.bin" {
		t.Fatalf("speed test URL = %q", ui.SpeedTestURL)
	}
	reloaded, err := newStore(config)
	if err != nil {
		t.Fatal(err)
	}
	reloadedUI, _, _ := reloaded.snapshot()
	if reloadedUI.UpstreamProxy != ui.UpstreamProxy {
		t.Fatalf("persisted upstream proxy = %q", reloadedUI.UpstreamProxy)
	}
	if reloadedUI.SpeedTestURL != ui.SpeedTestURL {
		t.Fatalf("persisted speed test URL = %q", reloadedUI.SpeedTestURL)
	}

	body, _ = json.Marshal(map[string]any{"upstream_proxy": "ftp://127.0.0.1:21"})
	request = httptest.NewRequest(http.MethodPost, "/api/update_settings", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	web.updateSettings(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid proxy returned %d: %s", recorder.Code, recorder.Body.String())
	}

	body, _ = json.Marshal(map[string]any{"speed_test_url": "file:///tmp/test.bin"})
	request = httptest.NewRequest(http.MethodPost, "/api/update_settings", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	web.updateSettings(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid speed URL returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDownloadSpeedUsesLocalProxy(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Host != "speed.invalid" {
			t.Errorf("unexpected speed target: %s", request.URL.String())
		}
		_, _ = writer.Write(bytes.Repeat([]byte("a"), 1<<20))
	}))
	defer proxyServer.Close()

	config := loadAppConfig()
	config.DataDir = t.TempDir()
	application, err := newStore(config)
	if err != nil {
		t.Fatal(err)
	}
	application.mu.Lock()
	application.ui.ProxyPort = proxyServer.Listener.Addr().(*net.TCPAddr).Port
	application.ui.SpeedTestURL = "http://speed.invalid/test.bin"
	application.mu.Unlock()
	web := newWebApplication(application, newVPNController(application))
	result := web.checkDownloadSpeed()
	if ok, _ := result["ok"].(bool); !ok {
		t.Fatalf("speed test failed: %+v", result)
	}
	if speed, _ := result["speed_mbps"].(float64); speed <= 0 {
		t.Fatalf("invalid speed result: %+v", result)
	}
	if size, _ := result["bytes"].(int64); size != 1<<20 {
		t.Fatalf("downloaded bytes = %d", size)
	}
}

func TestIndexShowsProxyAndSpeedFeatures(t *testing.T) {
	for _, expected := range []string{"net_upstream_proxy", "net_speed_test_url", "btn_test_speed", "proxy_speed_val", "节点延迟", "${latencyText}${testBtn}"} {
		if !strings.Contains(indexHTML, expected) {
			t.Fatalf("index is missing %q", expected)
		}
	}
}
