//go:build !linux

package main

import (
	"net"
	"time"
)

func dialVPN(address string, _ bool) (net.Conn, error) {
	return net.DialTimeout("tcp", address, 20*time.Second)
}
