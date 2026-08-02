package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caichengle666/gatepilot/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	config := store.AppConfig{ProxyHost: "127.0.0.1", ProxyPort: 0, ProxyMaxConnections: 8}
	server := NewServer(config)
	server.requireTun = false
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.listener = listener
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case server.limit <- struct{}{}:
				go func() {
					defer func() { <-server.limit }()
					server.handle(client)
				}()
			default:
				_ = client.Close()
			}
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func TestHTTPProxyRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "hello from backend")
	}))
	defer backend.Close()

	server := newTestServer(t)
	connection, err := net.Dial("tcp", server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", backend.URL, backend.URL)
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "hello from backend" {
		t.Fatalf("unexpected response: %d %q", response.StatusCode, body)
	}
}

func TestSOCKS5ProxyRequest(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		connection, err := backend.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.WriteString(connection, "socks5 ok")
	}()

	server := newTestServer(t)
	connection, err := net.Dial("tcp", server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = connection.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(backend.Addr().String())
	ip := net.ParseIP(host).To4()
	portNum := uint16(0)
	fmt.Sscanf(port, "%d", &portNum)
	connectRequest := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(portNum >> 8), byte(portNum)}
	_, _ = connection.Write(connectRequest)
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(connection, connectReply); err != nil {
		t.Fatal(err)
	}
	if connectReply[1] != 0 {
		t.Fatalf("SOCKS5 connect failed: %d", connectReply[1])
	}
	data, err := io.ReadAll(connection)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "socks5 ok" {
		t.Fatalf("unexpected SOCKS5 response: %q", data)
	}
}

func TestProxyAuthRejectsBadCredentials(t *testing.T) {
	server := newTestServer(t)
	server.username = "user"
	server.password = "pass"
	connection, err := net.Dial("tcp", server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = connection.Write([]byte("GET http://example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("user:wrong")) + "\r\n\r\n"))
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %d", response.StatusCode)
	}
}
