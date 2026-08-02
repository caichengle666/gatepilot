//go:build !windows

package main

const windowsElevation = false

func ensureAdminElevation() {}
