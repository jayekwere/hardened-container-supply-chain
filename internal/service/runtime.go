package service

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// CheckRuntime is an explicit diagnostic command for the deployed Linux process.
func CheckRuntime() error {
	if os.Getuid() != 65532 || os.Getgid() != 65532 {
		return fmt.Errorf("unexpected uid/gid")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	if fields["CapEff"] != "0000000000000000" || fields["CapPrm"] != "0000000000000000" || fields["NoNewPrivs"] != "1" {
		return fmt.Errorf("unsafe process status")
	}
	err = os.WriteFile("/write-probe", []byte("probe"), 0600)
	if !errors.Is(err, syscall.EROFS) {
		return fmt.Errorf("expected read-only rootfs, got %v", err)
	}
	return nil
}
