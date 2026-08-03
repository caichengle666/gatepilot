//go:build windows

package vpn

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func openVPNDeviceArguments(_ string, version float64, driver string) []string {
	arguments := []string{"--dev", "tun"}
	if version >= 2.6 && driver != "" {
		arguments = append(arguments, "--windows-driver", driver)
		if driver == "wintun" {
			arguments = append(arguments, "--dev-node", "OpenVPN")
		}
	}
	return arguments
}

func openVPNDriverCandidates(version float64, bundled bool) []string {
	if version < 2.6 {
		return []string{""}
	}
	if !bundled {
		return []string{"tap-windows6"}
	}
	return []string{"wintun", "tap-windows6"}
}

func openVPNUsesBundledCore(command string) bool {
	parts, err := splitCommandLine(command)
	if err != nil || len(parts) == 0 {
		return false
	}
	openVPNExecutable, err := exec.LookPath(parts[0])
	if err != nil {
		return false
	}
	applicationExecutable, err := os.Executable()
	return err == nil && isBundledOpenVPNExecutable(applicationExecutable, openVPNExecutable)
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

func hasTAPAdapter(tapctl string) bool {
	output, err := exec.Command(tapctl, "list").CombinedOutput()
	return err == nil && strings.TrimSpace(string(output)) != ""
}

// ensureTAPAdapter 确保系统有可用的 TAP 网卡：缺驱动则装驱动，缺网卡则建网卡。
func ensureTAPAdapter(openVPNCommand string) error {
	parts, err := splitCommandLine(openVPNCommand)
	if err != nil || len(parts) == 0 {
		return errors.New("无法解析 OpenVPN 命令")
	}
	openVPNExecutable, err := exec.LookPath(parts[0])
	if err != nil {
		return err
	}
	openVPNDir := filepath.Dir(openVPNExecutable)
	tapctl := filepath.Join(openVPNDir, "tapctl.exe")
	if _, statErr := os.Stat(tapctl); statErr != nil {
		return errors.New("便携包缺少 openvpn\\tapctl.exe，无法创建 TAP 备用网卡")
	}
	if hasTAPAdapter(tapctl) {
		return nil
	}

	// 1. 尝试安装 TAP 驱动（幂等：已装则 pnputil 直接跳过）
	infPath := filepath.Join(openVPNDir, "tap-driver", "OemVista.inf")
	if _, statErr := os.Stat(infPath); statErr != nil {
		return errors.New("便携包缺少 openvpn\\tap-driver\\OemVista.inf，无法安装 TAP 备用驱动")
	}
	pnputil := exec.Command("pnputil", "/add-driver", infPath, "/install")
	pnputil.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, runErr := pnputil.CombinedOutput(); runErr != nil {
		return errors.New("Windows 拒绝安装 TAP 备用驱动: " + strings.TrimSpace(string(output)))
	}

	// 2. 创建 TAP 网卡
	create := exec.Command(tapctl, "create")
	create.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, runErr := create.CombinedOutput(); runErr != nil {
		return errors.New("tapctl 创建 TAP 备用网卡失败: " + strings.TrimSpace(string(output)))
	}
	for attempt := 0; attempt < 20; attempt++ {
		if hasTAPAdapter(tapctl) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("TAP 备用驱动已安装，但 Windows 未创建对应虚拟网卡")
}
