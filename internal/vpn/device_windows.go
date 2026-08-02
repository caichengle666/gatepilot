//go:build windows

package vpn

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func openVPNDeviceArguments(_ string, version float64, driver string) []string {
	arguments := []string{"--dev", "tun"}
	if version >= 2.6 && driver != "" {
		arguments = append(arguments, "--windows-driver", driver)
	}
	return arguments
}

func openVPNDriverCandidates(version float64) []string {
	if version < 2.6 {
		return []string{""}
	}
	return []string{"wintun", "tap-windows6", "ovpn-dco"}
}

func shouldRetryOpenVPNDriver(err error) bool {
	var failure *openVPNFailure
	return errors.As(err, &failure) && (failure.code == "ERR_VPN_DRIVER" || failure.code == "ERR_VPN_PERMISSION")
}

func openVPNRouteArguments(routeNopull bool) []string {
	if routeNopull {
		return []string{"--pull-filter", "ignore", "redirect-gateway", "--pull-filter", "ignore", "route-gateway", "--route-nopull"}
	}
	return []string{"--pull-filter", "ignore", "dhcp-option"}
}

// hasTAPAdapter 检查系统里是否已存在 TAP-Windows6 网卡。
func hasTAPAdapter() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		lower := strings.ToLower(iface.Name)
		if strings.Contains(lower, "tap") {
			return true
		}
	}
	return false
}

// ensureTAPAdapter 确保系统有可用的 TAP 网卡：缺驱动则装驱动，缺网卡则建网卡。
func ensureTAPAdapter(openVPNCommand string) error {
	if hasTAPAdapter() {
		return nil
	}
	parts, err := splitCommandLine(openVPNCommand)
	if err != nil || len(parts) == 0 {
		return errors.New("无法解析 OpenVPN 命令")
	}
	openVPNExecutable, err := exec.LookPath(parts[0])
	if err != nil {
		return err
	}
	openVPNDir := filepath.Dir(openVPNExecutable)

	// 1. 尝试安装 TAP 驱动（幂等：已装则 pnputil 直接跳过）
	infPath := filepath.Join(openVPNDir, "tap-driver", "OemVista.inf")
	if _, statErr := os.Stat(infPath); statErr == nil {
		pnputil := exec.Command("pnputil", "/add-driver", infPath, "/install")
		pnputil.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if output, runErr := pnputil.CombinedOutput(); runErr != nil {
			return errors.New("安装 TAP 驱动失败: " + strings.TrimSpace(string(output)))
		}
	}

	// 2. 创建 TAP 网卡
	tapctl := filepath.Join(openVPNDir, "tapctl.exe")
	if _, statErr := os.Stat(tapctl); statErr != nil {
		return errors.New("未找到 tapctl.exe，无法创建 TAP 网卡")
	}
	create := exec.Command(tapctl, "create")
	create.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, runErr := create.CombinedOutput(); runErr != nil {
		return errors.New("tapctl 创建 TAP 网卡失败: " + strings.TrimSpace(string(output)))
	}
	return nil
}