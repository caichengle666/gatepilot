package main

import (
	"bytes"
	"encoding/json"
	"io"
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
	application.ui.SecretPath = "test-secret"
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
	response, err := client.Post(server.URL+"/test-secret/api/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login returned %s", response.Status)
	}
	response, err = client.Get(server.URL + "/test-secret/api/nodes")
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

	response, err = client.Get(server.URL + "/test-secret/")
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

	response, err = client.Get(server.URL + "/test-secret/api/gateway_status")
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

	response, err = client.Get(server.URL + "/test-secret/configs/JP_test.ovpn")
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
