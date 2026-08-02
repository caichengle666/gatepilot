package proxy

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caichengle666/gatepilot/internal/store"
)

// Server 是本地 HTTP/SOCKS5 代理服务器。
type Server struct {
	host       string
	port       int
	limit      chan struct{}
	username   string
	password   string
	requireTun bool
	mu         sync.Mutex
	listener   net.Listener
}

// NewServer 创建代理服务器。
func NewServer(config store.AppConfig) *Server {
	username := store.EnvString("LOCAL_PROXY_USER", store.Getenv("LOCAL_PROXY_USERNAME"))
	password := store.EnvString("LOCAL_PROXY_PASS", store.Getenv("LOCAL_PROXY_PASSWORD"))
	return &Server{
		host: config.ProxyHost, port: config.ProxyPort,
		limit:      make(chan struct{}, config.ProxyMaxConnections),
		username:   username,
		password:   password,
		requireTun: store.EnvBool("LOCAL_PROXY_BIND_TUN", true),
	}
}

// Serve 启动代理监听。
func (s *Server) Serve() error {
	s.mu.Lock()
	host, port := s.host, s.port
	s.mu.Unlock()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	log.Printf("HTTP/SOCKS5 proxy listening on %s", listener.Addr())
	for {
		client, acceptErr := listener.Accept()
		if acceptErr != nil {
			if errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			return acceptErr
		}
		select {
		case s.limit <- struct{}{}:
			go func() {
				defer func() { <-s.limit }()
				s.handle(client)
			}()
		default:
			_ = client.Close()
		}
	}
}

// ScheduleRestart 延迟重启代理监听。
func (s *Server) ScheduleRestart(port int) {
	go func() {
		time.Sleep(2 * time.Second)
		s.mu.Lock()
		listener := s.listener
		s.listener = nil
		s.port = port
		s.mu.Unlock()
		if listener != nil {
			_ = listener.Close()
		}
		if err := s.Serve(); err != nil {
			log.Printf("Local proxy restart failed: %v", err)
		}
	}()
}

func (s *Server) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Minute))
	first := []byte{0}
	if _, err := io.ReadFull(client, first); err != nil {
		return
	}
	if first[0] == 5 {
		s.handleSOCKS5(client)
		return
	}
	s.handleHTTP(client, first[0])
}

func (s *Server) authEnabled() bool {
	return s.username != "" || s.password != ""
}

func (s *Server) credentialsMatch(username, password string) bool {
	userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(s.username))
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(s.password))
	return userMatch&passwordMatch == 1
}

func readExact(connection net.Conn, size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := io.ReadFull(connection, data)
	return data, err
}

func (s *Server) handleSOCKS5(client net.Conn) {
	count, err := readExact(client, 1)
	if err != nil {
		return
	}
	methods, err := readExact(client, int(count[0]))
	if err != nil {
		return
	}
	method := byte(0)
	if s.authEnabled() {
		method = 2
	}
	if !bytes.Contains(methods, []byte{method}) {
		_, _ = client.Write([]byte{5, 255})
		return
	}
	_, _ = client.Write([]byte{5, method})
	if method == 2 && !s.readSOCKSAuth(client) {
		return
	}
	header, err := readExact(client, 4)
	if err != nil || header[0] != 5 || header[1] != 1 {
		_, _ = client.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	host, err := readSOCKSHost(client, header[3])
	if err != nil {
		return
	}
	portBytes, err := readExact(client, 2)
	if err != nil {
		return
	}
	upstream, err := DialVPN(net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), s.requireTun)
	if err != nil {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	_, _ = client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	relay(client, upstream)
}

func (s *Server) readSOCKSAuth(client net.Conn) bool {
	header, err := readExact(client, 2)
	if err != nil || header[0] != 1 {
		return false
	}
	username, err := readExact(client, int(header[1]))
	if err != nil {
		return false
	}
	length, err := readExact(client, 1)
	if err != nil {
		return false
	}
	password, err := readExact(client, int(length[0]))
	if err != nil || !s.credentialsMatch(string(username), string(password)) {
		_, _ = client.Write([]byte{1, 1})
		return false
	}
	_, _ = client.Write([]byte{1, 0})
	return true
}

func readSOCKSHost(client net.Conn, addressType byte) (string, error) {
	switch addressType {
	case 1:
		value, err := readExact(client, 4)
		return net.IP(value).String(), err
	case 3:
		length, err := readExact(client, 1)
		if err != nil {
			return "", err
		}
		value, err := readExact(client, int(length[0]))
		return string(value), err
	case 4:
		value, err := readExact(client, 16)
		return net.IP(value).String(), err
	default:
		return "", errors.New("unsupported SOCKS5 address type")
	}
}

func (s *Server) handleHTTP(client net.Conn, first byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{first}), client))
	request, err := http.ReadRequest(reader)
	if err != nil {
		writeProxyResponse(client, http.StatusBadRequest, "Bad Request")
		return
	}
	defer request.Body.Close()
	if s.authEnabled() && !s.authorizedHTTP(request.Header.Get("Proxy-Authorization")) {
		_, _ = io.WriteString(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=gatepilot\r\nContent-Length: 0\r\n\r\n")
		return
	}
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	if request.Method == http.MethodConnect {
		s.handleConnect(client, request.Host)
		return
	}
	target := request.URL.Host
	if target == "" {
		target = request.Host
	}
	if target == "" {
		writeProxyResponse(client, http.StatusBadRequest, "Missing Host")
		return
	}
	if _, _, splitErr := net.SplitHostPort(target); splitErr != nil {
		port := "80"
		if strings.EqualFold(request.URL.Scheme, "https") {
			port = "443"
		}
		target = net.JoinHostPort(target, port)
	}
	upstream, err := DialVPN(target, s.requireTun)
	if err != nil {
		writeProxyResponse(client, http.StatusBadGateway, "Bad Gateway")
		return
	}
	defer upstream.Close()
	request.RequestURI = ""
	if request.URL.Scheme == "" {
		request.URL.Scheme = "http"
	}
	if request.URL.Host == "" {
		request.URL.Host = request.Host
	}
	if err := request.Write(upstream); err != nil {
		return
	}
	relay(client, upstream)
}

func (s *Server) authorizedHTTP(header string) bool {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	credentials := strings.SplitN(string(decoded), ":", 2)
	return len(credentials) == 2 && s.credentialsMatch(credentials[0], credentials[1])
}

func (s *Server) handleConnect(client net.Conn, authority string) {
	target := authority
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	upstream, err := DialVPN(target, s.requireTun)
	if err != nil {
		writeProxyResponse(client, http.StatusBadGateway, "Bad Gateway")
		return
	}
	defer upstream.Close()
	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	relay(client, upstream)
}

func writeProxyResponse(connection net.Conn, status int, message string) {
	body := message + "\n"
	_, _ = fmt.Fprintf(connection, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body)
}

func relay(left, right net.Conn) {
	done := make(chan struct{}, 2)
	copyConnection := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		if tcp, ok := destination.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyConnection(left, right)
	go copyConnection(right, left)
	<-done
}
