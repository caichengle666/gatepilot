//go:build windows

package vpn

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	openVPNServiceName        = "GatePilotOpenVPN"
	openVPNServiceFlag        = "--openvpn-service"
	openVPNServiceDataDirFlag = "--openvpn-data-dir"
)

type openVPNServiceRequest struct {
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
	LogPath    string   `json:"log_path"`
}

type serviceOpenVPNProcess struct {
	done     chan error
	stopped  chan struct{}
	stopOnce sync.Once
}

func startOpenVPNProcess(command *exec.Cmd, windowsDriver string) (io.ReadCloser, managedOpenVPNProcess, <-chan error, error) {
	if windowsDriver != "wintun" {
		return startLocalOpenVPNProcess(command)
	}
	output, process, done, err := startServiceOpenVPNProcess(command)
	if err != nil {
		return nil, nil, nil, &openVPNFailure{code: "ERR_VPN_PERMISSION", message: "Wintun SYSTEM 服务不可用，回退 TAP: " + err.Error(), cause: err}
	}
	return output, process, done, nil
}

func startServiceOpenVPNProcess(command *exec.Cmd) (io.ReadCloser, managedOpenVPNProcess, <-chan error, error) {
	if err := ensureOpenVPNServiceInstalled(); err != nil {
		return nil, nil, nil, fmt.Errorf("OpenVPN SYSTEM 服务不可用: %w", err)
	}
	if err := stopOpenVPNService(5 * time.Second); err != nil {
		return nil, nil, nil, err
	}
	_, requestPath, logPath, err := openVPNServicePaths()
	if err != nil {
		return nil, nil, nil, err
	}
	request := openVPNServiceRequest{Executable: command.Path, Arguments: command.Args[1:], LogPath: logPath}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, nil, nil, err
	}
	temporaryPath := requestPath + ".tmp"
	if err := os.WriteFile(temporaryPath, encoded, 0o600); err != nil {
		return nil, nil, nil, err
	}
	if err := os.Rename(temporaryPath, requestPath); err != nil {
		return nil, nil, nil, err
	}
	_ = os.Remove(logPath)

	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, nil, err
	}
	service, err := manager.OpenService(openVPNServiceName)
	if err != nil {
		manager.Disconnect()
		return nil, nil, nil, err
	}
	if err := service.Start(); err != nil {
		service.Close()
		manager.Disconnect()
		return nil, nil, nil, fmt.Errorf("启动 OpenVPN SYSTEM 服务失败: %w", err)
	}
	service.Close()
	manager.Disconnect()

	if err := waitForOpenVPNServiceStart(logPath, 8*time.Second); err != nil {
		return nil, nil, nil, err
	}
	process := &serviceOpenVPNProcess{done: make(chan error, 1), stopped: make(chan struct{})}
	go process.watch()
	reader, writer := io.Pipe()
	go tailOpenVPNServiceLog(logPath, process.stopped, writer)
	return reader, process, process.done, nil
}

func (process *serviceOpenVPNProcess) watch() {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	defer close(process.done)
	defer close(process.stopped)
	for range ticker.C {
		status, err := queryOpenVPNService()
		if err != nil {
			process.done <- err
			return
		}
		if status.State == svc.Stopped {
			process.done <- errors.New("OpenVPN SYSTEM 服务已停止")
			return
		}
	}
}

func (process *serviceOpenVPNProcess) Stop() {
	process.stopOnce.Do(func() {
		_ = stopOpenVPNService(5 * time.Second)
	})
}

func tailOpenVPNServiceLog(path string, stopped <-chan struct{}, writer *io.PipeWriter) {
	defer writer.Close()
	var file *os.File
	var offset int64
	buffer := make([]byte, 32<<10)
	for {
		if file == nil {
			opened, err := os.Open(path)
			if err == nil {
				file = opened
				if offset > 0 {
					_, _ = file.Seek(offset, io.SeekStart)
				}
			}
		}
		if file != nil {
			count, readErr := file.Read(buffer)
			if count > 0 {
				offset += int64(count)
				if _, err := writer.Write(buffer[:count]); err != nil {
					file.Close()
					return
				}
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				file.Close()
				file = nil
			}
		}
		select {
		case <-stopped:
			if file != nil {
				file.Close()
			}
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func RunWindowsOpenVPNService(arguments []string) bool {
	if !containsArgument(arguments, openVPNServiceFlag) {
		return false
	}
	if dataDir, ok := argumentValue(arguments, openVPNServiceDataDirFlag); ok {
		_ = os.Setenv("VPNGATE_DATA_DIR", dataDir)
	}
	if err := svc.Run(openVPNServiceName, &openVPNServiceHandler{}); err != nil {
		_, _, logPath, pathErr := openVPNServicePaths()
		if pathErr == nil {
			_ = os.WriteFile(logPath+".service-error", []byte(err.Error()), 0o600)
		}
	}
	return true
}

type openVPNServiceHandler struct{}

func (*openVPNServiceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	command, logFile, err := commandFromOpenVPNServiceRequest()
	if err != nil {
		writeOpenVPNServiceError(err)
		return false, 1
	}
	defer logFile.Close()
	defer releaseWintunAdapter()
	if err := command.Start(); err != nil {
		_, _ = fmt.Fprintf(logFile, "OpenVPN SYSTEM service start failed: %v\n", err)
		return false, 2
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case <-done:
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				_ = command.Process.Signal(os.Interrupt)
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					_ = command.Process.Kill()
					<-done
				}
				return false, 0
			}
		}
	}
}

func commandFromOpenVPNServiceRequest() (*exec.Cmd, *os.File, error) {
	_, requestPath, expectedLogPath, err := openVPNServicePaths()
	if err != nil {
		return nil, nil, err
	}
	encoded, err := os.ReadFile(requestPath)
	if err != nil {
		return nil, nil, err
	}
	var request openVPNServiceRequest
	if err := json.Unmarshal(encoded, &request); err != nil {
		return nil, nil, err
	}
	serviceExecutable, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	expectedExecutable := filepath.Join(filepath.Dir(serviceExecutable), "openvpn", "openvpn.exe")
	if !sameWindowsPath(request.Executable, expectedExecutable) {
		return nil, nil, errors.New("OpenVPN SYSTEM 服务拒绝非内置 OpenVPN 可执行文件")
	}
	if !sameWindowsPath(request.LogPath, expectedLogPath) {
		return nil, nil, errors.New("OpenVPN SYSTEM 服务日志路径无效")
	}
	if err := validateOpenVPNServiceArguments(request.Arguments); err != nil {
		return nil, nil, err
	}
	logFile, err := os.OpenFile(expectedLogPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	ensureWintunAdapter(logFile, filepath.Dir(expectedExecutable))
	command := exec.Command(expectedExecutable, request.Arguments...)
	command.Dir = filepath.Dir(expectedExecutable)
	command.Stdout = logFile
	command.Stderr = logFile
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return command, logFile, nil
}

func validateOpenVPNServiceArguments(arguments []string) error {
	allowedValues := map[string]int{
		"--config": 1, "--pull-filter": 2, "--route-delay": 1,
		"--connect-retry-max": 1, "--connect-timeout": 1, "--auth-user-pass": 1,
		"--verb": 1, "--dev": 1, "--dev-node": 1, "--windows-driver": 1, "--data-ciphers": 1,
		"--data-ciphers-fallback": 1, "--ncp-ciphers": 1,
	}
	allowedFlags := map[string]bool{"--auth-nocache": true, "--route-nopull": true}
	hasConfig := false
	hasWintun := false
	for index := 0; index < len(arguments); {
		option := strings.ToLower(arguments[index])
		if allowedFlags[option] {
			index++
			continue
		}
		if option == "--socks-proxy" || option == "--http-proxy" {
			if index+2 >= len(arguments) {
				return fmt.Errorf("OpenVPN SYSTEM 服务拒绝不完整参数 %q", arguments[index])
			}
			index += 3
			if index < len(arguments) && !strings.HasPrefix(arguments[index], "--") {
				index++
			}
			continue
		}
		valueCount, ok := allowedValues[option]
		if !ok || index+valueCount >= len(arguments) {
			return fmt.Errorf("OpenVPN SYSTEM 服务拒绝参数 %q", arguments[index])
		}
		if option == "--config" {
			hasConfig = true
		}
		if option == "--windows-driver" && strings.EqualFold(arguments[index+1], "wintun") {
			hasWintun = true
		}
		index += valueCount + 1
	}
	if !hasConfig || !hasWintun {
		return errors.New("OpenVPN SYSTEM 服务请求缺少配置或 Wintun 驱动参数")
	}
	return nil
}

func ensureOpenVPNServiceInstalled() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	dataDir, _, _, err := openVPNServicePaths()
	if err != nil {
		return err
	}
	serviceArguments := []string{openVPNServiceFlag, openVPNServiceDataDirFlag, dataDir}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(openVPNServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		service, err = manager.CreateService(openVPNServiceName, executable, mgr.Config{
			ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
			StartType:    mgr.StartManual,
			ErrorControl: mgr.ErrorNormal,
			DisplayName:  "GatePilot OpenVPN SYSTEM Service",
			Description:  "Runs the bundled OpenVPN core as LocalSystem so the Wintun driver can be used.",
		}, serviceArguments...)
	}
	if err != nil {
		return err
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		return err
	}
	expectedPath := quoteWindowsServiceArgument(executable) + " " + openVPNServiceFlag + " " + openVPNServiceDataDirFlag + " " + quoteWindowsServiceArgument(dataDir)
	if !strings.EqualFold(strings.TrimSpace(config.BinaryPathName), expectedPath) || !strings.EqualFold(config.ServiceStartName, "LocalSystem") {
		config.BinaryPathName = expectedPath
		config.StartType = mgr.StartManual
		config.ServiceType = windows.SERVICE_WIN32_OWN_PROCESS
		config.DisplayName = "GatePilot OpenVPN SYSTEM Service"
		config.Description = "Runs the bundled OpenVPN core as LocalSystem so the Wintun driver can be used."
		config.ServiceStartName = "LocalSystem"
		config.Password = ""
		if err := service.UpdateConfig(config); err != nil {
			return err
		}
	}
	return nil
}

// PrepareWindowsOpenVPNService 在启动时预安装或修复便携版 OpenVPN SYSTEM 服务。
func PrepareWindowsOpenVPNService(openVPNCommand string) (bool, error) {
	parts, err := splitCommandLine(openVPNCommand)
	if err != nil || len(parts) == 0 {
		return false, errors.New("无法解析 OpenVPN 命令")
	}
	openVPNExecutable, err := exec.LookPath(parts[0])
	if err != nil {
		return false, err
	}
	applicationExecutable, err := os.Executable()
	if err != nil {
		return false, err
	}
	if !isBundledOpenVPNExecutable(applicationExecutable, openVPNExecutable) {
		return false, nil
	}
	if err := ensureOpenVPNServiceInstalled(); err != nil {
		return true, err
	}
	return true, nil
}

// RemoveWindowsOpenVPNService 停止并删除 GatePilot 自己安装的 SYSTEM 服务。
func RemoveWindowsOpenVPNService() error {
	if err := stopOpenVPNService(5 * time.Second); err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(openVPNServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Delete()
}

func openVPNServicePaths() (string, string, string, error) {
	root := os.Getenv("VPNGATE_DATA_DIR")
	if strings.TrimSpace(root) == "" {
		executable, err := os.Executable()
		if err != nil {
			return "", "", "", err
		}
		root = filepath.Join(filepath.Dir(executable), "vpngate_data")
	}
	return root, filepath.Join(root, "openvpn-service-request.json"), filepath.Join(root, "openvpn-service.log"), nil
}

var wintunHeldAdapter uintptr
var wintunHeldDLL *windows.DLL

func ensureWintunAdapter(logFile *os.File, dllDir string) {
	if logFile == nil {
		return
	}
	dll, err := windows.LoadDLL(filepath.Join(dllDir, "wintun.dll"))
	if err != nil {
		fmt.Fprintf(logFile, "[WintunPrep] LoadDLL failed: %v\n", err)
		return
	}
	create, err := dll.FindProc("WintunCreateAdapter")
	if err != nil {
		fmt.Fprintf(logFile, "[WintunPrep] FindProc create failed: %v\n", err)
		return
	}
	openProc, _ := dll.FindProc("WintunOpenAdapter")
	name, _ := windows.UTF16PtrFromString("OpenVPN")
	if openProc != nil {
		if existing, _, _ := openProc.Call(uintptr(unsafe.Pointer(name))); existing != 0 {
			wintunHeldAdapter = existing
			wintunHeldDLL = dll
			fmt.Fprintf(logFile, "[WintunPrep] OpenAdapter OK (existing, held)\n")
			return
		}
	}
	tunnel, _ := windows.UTF16PtrFromString("OpenVPN")
	guid := &windows.GUID{Data1: 0x2E4F2D4A, Data2: 0x1A3B, Data3: 0x4C5D, Data4: [8]byte{0x6E, 0x7F, 0x80, 0x91, 0xA2, 0xB3, 0xC4, 0xD5}}
	adapter, _, callErr := create.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(tunnel)), uintptr(unsafe.Pointer(guid)))
	if adapter == 0 {
		fmt.Fprintf(logFile, "[WintunPrep] CreateAdapter FAILED errno=%v\n", callErr)
		return
	}
	wintunHeldAdapter = adapter
	wintunHeldDLL = dll
	fmt.Fprintf(logFile, "[WintunPrep] CreateAdapter OK (held open)\n")
}

func releaseWintunAdapter() {
	if wintunHeldAdapter != 0 && wintunHeldDLL != nil {
		if closeProc, err := wintunHeldDLL.FindProc("WintunCloseAdapter"); err == nil {
			_, _, _ = closeProc.Call(wintunHeldAdapter)
		}
		wintunHeldAdapter = 0
	}
}
func writeOpenVPNServiceError(serviceErr error) {
	_, _, logPath, err := openVPNServicePaths()
	if err != nil {
		return
	}
	_ = os.WriteFile(logPath, []byte("OpenVPN SYSTEM service error: "+serviceErr.Error()+"\n"), 0o600)
}

func queryOpenVPNService() (svc.Status, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return svc.Status{}, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(openVPNServiceName)
	if err != nil {
		return svc.Status{}, err
	}
	defer service.Close()
	return service.Query()
}

func stopOpenVPNService(timeout time.Duration) error {
	status, err := queryOpenVPNService()
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) || status.State == svc.Stopped {
		return nil
	}
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	service, err := manager.OpenService(openVPNServiceName)
	if err != nil {
		manager.Disconnect()
		return err
	}
	_, controlErr := service.Control(svc.Stop)
	service.Close()
	manager.Disconnect()
	if controlErr != nil && !errors.Is(controlErr, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return controlErr
	}
	return waitForOpenVPNServiceState(svc.Stopped, timeout)
}

func waitForOpenVPNServiceState(target svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := queryOpenVPNService()
		if err == nil && status.State == target {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("等待 OpenVPN SYSTEM 服务进入状态 %d 超时", target)
}

func waitForOpenVPNServiceStart(logPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := queryOpenVPNService()
		if err == nil {
			switch status.State {
			case svc.Running:
				return nil
			case svc.Stopped:
				if output, readErr := os.ReadFile(logPath); readErr == nil && len(output) > 0 {
					return fmt.Errorf("OpenVPN SYSTEM 服务启动后立即停止: %s", strings.TrimSpace(string(output)))
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.New("等待 OpenVPN SYSTEM 服务启动超时")
}

func containsArgument(arguments []string, target string) bool {
	for _, argument := range arguments {
		if argument == target {
			return true
		}
	}
	return false
}

func argumentValue(arguments []string, target string) (string, bool) {
	for index, argument := range arguments {
		if argument == target && index+1 < len(arguments) {
			return arguments[index+1], true
		}
	}
	return "", false
}

func sameWindowsPath(left, right string) bool {
	leftPath, leftErr := filepath.Abs(left)
	rightPath, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && strings.EqualFold(filepath.Clean(leftPath), filepath.Clean(rightPath))
}

func quoteWindowsServiceArgument(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}
