package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/caichengle666/gatepilot/internal/store"
)

func ensureStartupPortsAvailable(config store.AppConfig) error {
	checks := []struct {
		name string
		host string
		port int
	}{
		{name: "Web 管理端口", host: config.UIHost, port: config.UIPort},
		{name: "本地代理端口", host: config.ProxyHost, port: config.ProxyPort},
	}
	for _, check := range checks {
		address := net.JoinHostPort(check.host, strconv.Itoa(check.port))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return fmt.Errorf("%s %s 已被占用；请退出已有实例或修改端口", check.name, address)
		}
		_ = listener.Close()
	}
	return nil
}
