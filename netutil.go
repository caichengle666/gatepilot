package main

import (
	"net"
	"strconv"
	"time"
)

func netDialTimeout(network, host string, port int, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, net.JoinHostPort(host, strconv.Itoa(port)), timeout)
}
