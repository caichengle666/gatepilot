//go:build !linux && !windows

package vpn

import "time"

func setupPolicyRouting(_ string) {}

func cleanupPolicyRouting() {}

func preparePolicyRouting() {}

func waitForVPNReady(_ time.Duration) error { return nil }
