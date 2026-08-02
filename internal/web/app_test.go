package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caichengle666/gatepilot/internal/store"
	"github.com/caichengle666/gatepilot/internal/vpn"
)

func TestWebLoginAndAPIs(t *testing.T) {
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	application.UpdateUI(func(ui *store.UIConfig) error {
		ui.SecretPath = "testsecret"
		ui.Username = "admin"
		ui.Password = "secret"
		return nil
	})
	vpnCtrl := vpn.NewController(application)
	server := httptest.NewServer(NewApplication(application, vpnCtrl))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	response, err := client.Get(server.URL + "/testsecret/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "登录") {
		preview := body
		if len(preview) > 100 {
			preview = preview[:100]
		}
		t.Fatalf("expected login page, got status=%s body=%q", response.Status, string(preview))
	}

	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "secret"})
	response, err = client.Post(server.URL+"/testsecret/api/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %s", response.Status)
	}

	response, err = client.Get(server.URL + "/testsecret/api/nodes")
	if err != nil {
		t.Fatal(err)
	}
	var nodesPayload struct {
		Nodes []any `json:"nodes"`
	}
	if err := json.NewDecoder(response.Body).Decode(&nodesPayload); err != nil {
		_ = response.Body.Close()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("nodes API failed: %s", response.Status)
	}

	response, err = client.Get(server.URL + "/testsecret/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if !strings.Contains(string(body), "GatePilot") && !strings.Contains(string(body), "管理系统") {
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
}

func TestCredentialUpdateKeepsServerAvailable(t *testing.T) {
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	application.UpdateUI(func(ui *store.UIConfig) error {
		ui.SecretPath = "testsecret"
		ui.Username = "test-user"
		ui.Password = "old-password"
		return nil
	})
	server := httptest.NewServer(NewApplication(application, vpn.NewController(application)))
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
	ui, _, _ := application.Snapshot()
	updateBody, _ := json.Marshal(map[string]any{
		"username": "test-user", "password": "new-password", "port": ui.Port, "secret_path": "testsecret",
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

func TestUpdateSettingsPersistsNetworkDownloads(t *testing.T) {
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	webApp := NewApplication(application, vpn.NewController(application))
	body, _ := json.Marshal(map[string]any{
		"upstream_proxy": "127.0.0.1:7890",
		"speed_test_url": "https://example.com/download?bytes=1000000",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/update_settings", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	webApp.updateSettings(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update returned %d: %s", recorder.Code, recorder.Body.String())
	}
	ui, _, _ := application.Snapshot()
	if ui.UpstreamProxy != "http://127.0.0.1:7890" {
		t.Fatalf("upstream proxy = %q", ui.UpstreamProxy)
	}
	if ui.SpeedTestURL != "https://example.com/download?bytes=1000000" {
		t.Fatalf("speed test URL = %q", ui.SpeedTestURL)
	}
	reloaded, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	reloadedUI, _, _ := reloaded.Snapshot()
	if reloadedUI.UpstreamProxy != ui.UpstreamProxy {
		t.Fatalf("persisted upstream proxy = %q", reloadedUI.UpstreamProxy)
	}
	if reloadedUI.SpeedTestURL != ui.SpeedTestURL {
		t.Fatalf("persisted speed test URL = %q", reloadedUI.SpeedTestURL)
	}

	body, _ = json.Marshal(map[string]any{"upstream_proxy": "ftp://127.0.0.1:21"})
	request = httptest.NewRequest(http.MethodPost, "/api/update_settings", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	webApp.updateSettings(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid proxy returned %d: %s", recorder.Code, recorder.Body.String())
	}

	body, _ = json.Marshal(map[string]any{"speed_test_url": "ftp://example.com/file"})
	request = httptest.NewRequest(http.MethodPost, "/api/update_settings", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	webApp.updateSettings(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid speed test URL returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestMeasureDownloadCapsBytes(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 256<<10)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	const limit int64 = 128 << 10
	result, err := measureDownload(context.Background(), server.Client(), server.URL, limit)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Bytes != limit || result.LimitBytes != limit || result.Mbps <= 0 {
		t.Fatalf("unexpected speed test result: %+v", result)
	}
}

func TestSpeedTestAPIUsesConfiguredLocalProxy(t *testing.T) {
	for _, name := range []string{"LOCAL_PROXY_USER", "LOCAL_PROXY_PASS", "LOCAL_PROXY_USERNAME", "LOCAL_PROXY_PASSWORD"} {
		t.Setenv(name, "")
	}
	var proxyCalled atomic.Bool
	proxyServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		proxyCalled.Store(true)
		_, _ = writer.Write(bytes.Repeat([]byte("z"), 64<<10))
	}))
	defer proxyServer.Close()
	parsedProxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyPort, err := strconv.Atoi(parsedProxyURL.Port())
	if err != nil {
		t.Fatal(err)
	}

	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := application.UpdateUI(func(ui *store.UIConfig) error {
		ui.SecretPath = "testsecret"
		ui.Username = "admin"
		ui.Password = "secret"
		ui.ProxyPort = proxyPort
		ui.SpeedTestURL = "http://speed.example/download"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewApplication(application, vpn.NewController(application)))
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "secret"})
	response, err := client.Post(server.URL+"/testsecret/api/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	speedBody, _ := json.Marshal(map[string]string{"url": "http://speed.example/download"})
	response, err = client.Post(server.URL+"/testsecret/api/speed_test", "application/json", bytes.NewReader(speedBody))
	if err != nil {
		t.Fatal(err)
	}
	var result speedTestResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		_ = response.Body.Close()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !result.OK || result.Bytes != 64<<10 {
		t.Fatalf("unexpected speed test response: status=%s result=%+v", response.Status, result)
	}
	if !proxyCalled.Load() {
		t.Fatal("speed test did not use the configured local proxy")
	}
}

func TestUpdateSettingsFixedIPDoesNotDeadlock(t *testing.T) {
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	webApp := NewApplication(application, vpn.NewController(application))
	body, _ := json.Marshal(map[string]any{"routing_mode": "fixed_ip"})
	request := httptest.NewRequest(http.MethodPost, "/api/update_settings", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		webApp.updateSettings(recorder, request)
		close(done)
	}()

	select {
	case <-done:
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("fixed IP without an active node returned %d: %s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fixed IP settings update deadlocked")
	}
}

func TestIndexShowsNetworkSettingsAndNodeLatency(t *testing.T) {
	for _, expected := range []string{
		"net_upstream_proxy", "net_speed_test_url", "runSpeedTest()",
		"单次最多读取 20 MB", "节点延迟", "${latencyText}${testBtn}",
	} {
		if !strings.Contains(indexHTML, expected) {
			t.Fatalf("index is missing %q", expected)
		}
	}
}

func TestAutoSwitchFallbackSkipsUDPAfterTwoFailures(t *testing.T) {
	config := store.LoadAppConfig()
	config.DataDir = t.TempDir()
	config.DisableBackground = true
	application, err := store.New(config)
	if err != nil {
		t.Fatal(err)
	}
	application.UpdateUI(func(ui *store.UIConfig) error {
		ui.RoutingMode = "auto"
		ui.ConnectionEnabled = true
		return nil
	})
	application.Nodes = []store.Node{
		{ID: "udp", Protocol: "udp", ProbeStatus: "available"},
		{ID: "tcp", Protocol: "tcp", ProbeStatus: "available"},
	}
	server := NewApplication(application, vpn.NewController(application))
	server.autoSwitch(2)
	_, state, _ := application.Snapshot()
	if state.LastCheckMessage != "正在连接节点 tcp" {
		t.Fatalf("last check message = %q", state.LastCheckMessage)
	}
}
