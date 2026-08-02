package vpn

import (
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

type managedOpenVPNProcess interface {
	Stop()
}

type localOpenVPNProcess struct {
	command  *exec.Cmd
	stopOnce sync.Once
}

func startLocalOpenVPNProcess(command *exec.Cmd) (io.ReadCloser, managedOpenVPNProcess, <-chan error, error) {
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		_ = output.Close()
		return nil, nil, nil, err
	}
	process := &localOpenVPNProcess{command: command}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
		close(done)
	}()
	return output, process, done, nil
}

func (process *localOpenVPNProcess) Stop() {
	process.stopOnce.Do(func() {
		if process.command == nil || process.command.Process == nil {
			return
		}
		_ = process.command.Process.Signal(os.Interrupt)
		time.Sleep(250 * time.Millisecond)
		_ = process.command.Process.Kill()
	})
}
