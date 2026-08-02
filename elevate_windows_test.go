//go:build windows

package main

import "testing"

func TestQuoteWindowsArguments(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "simple", want: `"simple"`},
		{input: "", want: `""`},
		{input: `D:\测试专用\gatepilot\.codex-run\gatepilot.exe`, want: `"D:\测试专用\gatepilot\.codex-run\gatepilot.exe"`},
		{input: `path with space`, want: `"path with space"`},
		{input: `quote"inside`, want: `"quote\"inside"`},
		{input: `trailing\`, want: `"trailing\\"`},
	}
	for _, test := range tests {
		if got := quoteWindowsArgument(test.input); got != test.want {
			t.Fatalf("quoteWindowsArgument(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
