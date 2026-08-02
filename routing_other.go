//go:build !linux && !windows

package main

func setupPolicyRouting(_ string) {}

func cleanupPolicyRouting() {}

func preparePolicyRouting() {}
