package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPProxyRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "through-proxy")
	}))
	defer backend.Close()
	client, proxy := net.Pipe()
	server := &proxyServer{limit: make(chan struct{}, 1), requireTun: false}
	go server.handle(proxy)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	request := "GET " + backend.URL + "/check HTTP/1.1\r\nHost: " + strings.TrimPrefix(backend.URL, "http://") + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "through-proxy" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestSOCKS5ProxyRequest(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	backendDone := make(chan error, 1)
	go func() {
		connection, acceptErr := backend.Accept()
		if acceptErr != nil {
			backendDone <- acceptErr
			return
		}
		defer connection.Close()
		payload := make([]byte, 4)
		if _, readErr := io.ReadFull(connection, payload); readErr != nil {
			backendDone <- readErr
			return
		}
		if string(payload) != "ping" {
			backendDone <- errors.New("unexpected SOCKS5 payload")
			return
		}
		_, writeErr := connection.Write([]byte("pong"))
		backendDone <- writeErr
	}()

	client, proxy := net.Pipe()
	server := &proxyServer{limit: make(chan struct{}, 1), requireTun: false}
	go server.handle(proxy)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if response[0] != 5 || response[1] != 0 {
		t.Fatalf("unexpected SOCKS5 greeting response: %v", response)
	}

	address := backend.Addr().(*net.TCPAddr)
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], uint16(address.Port))
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("unexpected SOCKS5 connect response: %v", reply)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(client, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "pong" {
		t.Fatalf("unexpected SOCKS5 response: %q", payload)
	}
	if err := <-backendDone; err != nil {
		t.Fatal(err)
	}
}
