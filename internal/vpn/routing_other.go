//go:build !linux && !windows

package vpn

import "time"

func setupPolicyRouting(_ string) {}

func setupDevicePolicyRouting(_ string, _ int) {}

func setupEndpointMainRoute(_ string, _ int) bool { return false }

func cleanupEndpointMainRoute(_ string, _ int) {}

func cleanupPolicyRouting() {}

func cleanupDevicePolicyRouting(_ string, _ int) {}

func preparePolicyRouting() {}

func openVPNControlArguments(_ string) []string { return nil }

func waitForVPNReady(_ time.Duration) error { return nil }

func waitForDeviceReady(_ string, _ time.Duration) error { return nil }
