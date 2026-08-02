//go:build !windows

package main

func acquireInstanceLock() (func(), error) {
	return func() {}, nil
}
