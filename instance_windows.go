//go:build windows

package main

import (
	"errors"
	"syscall"
	"unsafe"
)

const gatePilotInstanceMutex = `Local\GatePilot-SingleInstance`

func acquireInstanceLock() (func(), error) {
	name, err := syscall.UTF16PtrFromString(gatePilotInstanceMutex)
	if err != nil {
		return nil, err
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutex := kernel32.NewProc("CreateMutexW")
	closeHandle := kernel32.NewProc("CloseHandle")
	handle, _, callErr := createMutex.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return nil, callErr
	}
	if errors.Is(callErr, syscall.Errno(183)) {
		_, _, _ = closeHandle.Call(handle)
		return nil, errors.New("已有一个 GatePilot 实例正在运行；如需重新启动，请先退出现有实例")
	}
	return func() { _, _, _ = closeHandle.Call(handle) }, nil
}
