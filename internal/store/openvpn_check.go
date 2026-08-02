package store

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// OpenVPNStatus 检查当前 OpenVPN 命令是否可用，并返回用户可见的安装指引。
func OpenVPNStatus(command string) (ok bool, message string) {
	parts, err := splitOpenVPNCommand(command)
	if err != nil || len(parts) == 0 {
		return false, openVPNInstallHint("OPENVPN_CMD 配置无效，请重新指定 OpenVPN 可执行文件路径。")
	}
	if _, err := exec.LookPath(parts[0]); err != nil {
		return false, openVPNInstallHint("找不到 OpenVPN 核心程序。")
	}
	checkCommand := exec.Command(parts[0], append(parts[1:], "--version")...)
	checkCommand.WaitDelay = 5 * time.Second
	output, err := checkCommand.CombinedOutput()
	if err != nil {
		return false, openVPNInstallHint("OpenVPN 无法启动: " + strings.TrimSpace(string(output)))
	}
	return true, ""
}

func openVPNInstallHint(problem string) string {
	switch runtime.GOOS {
	case "windows":
		return problem + " 请下载 Windows 便携版 zip，或在 gatepilot.exe 旁放置 openvpn\\openvpn.exe 及配套 DLL；也可安装 OpenVPN Community。"
	case "darwin":
		return problem + " macOS 请先安装 OpenVPN：brew install openvpn，或通过 OPENVPN_CMD 指定 openvpn 路径。"
	default:
		return problem + " Linux 请安装 OpenVPN：Debian/Ubuntu 执行 apt install openvpn；Alpine 执行 apk add openvpn；RHEL/Rocky 执行 dnf install openvpn。"
	}
}

func splitOpenVPNCommand(value string) ([]string, error) {
	parts := []string{}
	var current strings.Builder
	var quote rune
	escaped := false
	tokenStarted := false
	flush := func() {
		if tokenStarted {
			parts = append(parts, current.String())
			current.Reset()
			tokenStarted = false
		}
	}
	for _, character := range strings.TrimSpace(value) {
		if escaped {
			current.WriteRune(character)
			tokenStarted = true
			escaped = false
			continue
		}
		switch {
		case character == '\\':
			escaped = true
			tokenStarted = true
		case quote != 0:
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			tokenStarted = true
		case character == '"' || character == '\'':
			quote = character
			tokenStarted = true
		case character == ' ' || character == '\t':
			flush()
		default:
			current.WriteRune(character)
			tokenStarted = true
		}
	}
	if quote != 0 {
		return nil, errors.New("命令行引号未闭合")
	}
	flush()
	return parts, nil
}
