//go:build windows

package main

import (
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	elevationFlag    = "--elevated"
	noElevationFlag  = "--no-elevate"
	windowsElevation = true
)

func hasFlag(arguments []string, flag string) bool {
	for _, argument := range arguments {
		if argument == flag {
			return true
		}
	}
	return false
}

func isElevated() bool {
	var token syscall.Token
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	if err := syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	var elevation uint32
	var returned uint32
	err = syscall.GetTokenInformation(token, syscall.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returned)
	return err == nil && elevation != 0
}

func ensureAdminElevation() {
	arguments := os.Args[1:]
	if hasFlag(arguments, noElevationFlag) || hasFlag(arguments, elevationFlag) || isElevated() {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		log.Printf("自动管理员提权失败，无法获取可执行文件路径: %v", err)
		return
	}
	arguments = append(arguments, elevationFlag)
	parameters := strings.Join(quoteWindowsArguments(arguments), " ")
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(executable)
	params, _ := syscall.UTF16PtrFromString(parameters)
	directory, _ := syscall.UTF16PtrFromString("")
	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecute := shell32.NewProc("ShellExecuteW")
	result, _, callErr := shellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(directory)), 1)
	if result <= 32 {
		log.Printf("自动管理员提权未成功（UAC 可能被取消，ShellExecute=%d）；OpenVPN Wintun 网口需要管理员权限。可使用 --no-elevate 禁止自动提权。", result)
		if callErr != nil && callErr != syscall.Errno(0) {
			log.Printf("ShellExecute 错误: %v", callErr)
		}
		return
	}
	log.Printf("已请求管理员权限并启动新进程，当前非管理员进程退出。")
	os.Exit(0)
}

func quoteWindowsArguments(arguments []string) []string {
	quoted := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		quoted = append(quoted, quoteWindowsArgument(argument))
	}
	return quoted
}

func quoteWindowsArgument(argument string) string {
	if argument == "" {
		return `""`
	}
	var builder strings.Builder
	builder.WriteByte('"')
	for _, character := range argument {
		switch character {
		case '"':
			builder.WriteString(`\"`)
		default:
			builder.WriteRune(character)
		}
	}
	if strings.HasSuffix(argument, `\`) {
		builder.WriteByte('\\')
	}
	builder.WriteByte('"')
	return builder.String()
}
