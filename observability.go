package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type logEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Module    string `json:"module"`
	Message   string `json:"message"`
}

type blacklistEntry struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Reason   string `json:"reason"`
	MarkedAt int64  `json:"marked_at"`
	Until    int64  `json:"until"`
}

var observationMu sync.Mutex

func (application *store) logEvent(level, module, message string) {
	entry := logEntry{Timestamp: time.Now().Format(time.RFC3339), Level: strings.ToUpper(level), Module: module, Message: message}
	fmt.Printf("[%s] [%s] %s\n", entry.Level, entry.Module, entry.Message)
	observationMu.Lock()
	defer observationMu.Unlock()
	logsDir := filepath.Join(application.config.DataDir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return
	}
	path := filepath.Join(logsDir, time.Now().Format("2006-01-02")+".json")
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = file.Write(append(data, '\n'))
		_ = file.Close()
	}
	application.cleanupLogs(logsDir)
}

func (application *store) cleanupLogs(logsDir string) {
	entries, _ := os.ReadDir(logsDir)
	cutoff := time.Now().Add(-72 * time.Hour)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") && !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		info, err := entry.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(logsDir, entry.Name()))
		}
	}
}

func (application *store) recentLogs(limit int) []logEntry {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	observationMu.Lock()
	defer observationMu.Unlock()
	today := time.Now().Format("2006-01-02")
	names := []string{today + ".json", today + ".jsonl"}
	result := make([]logEntry, 0, limit)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(application.config.DataDir, "logs", name))
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			var entry logEntry
			if json.Unmarshal([]byte(line), &entry) == nil {
				result = append(result, entry)
			}
		}
	}
	sort.SliceStable(result, func(left, right int) bool { return result[left].Timestamp < result[right].Timestamp })
	if len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

func (application *store) loadBlacklist() map[string]blacklistEntry {
	entries := map[string]blacklistEntry{}
	_ = readJSON(filepath.Join(application.config.DataDir, "blacklist.json"), &entries)
	now := time.Now().Unix()
	changed := false
	for id, entry := range entries {
		if entry.Until <= now {
			delete(entries, id)
			changed = true
		}
	}
	if changed {
		_ = writeJSON(filepath.Join(application.config.DataDir, "blacklist.json"), entries)
	}
	return entries
}

func (application *store) markBlacklisted(candidate node, reason string) {
	if candidate.ID == "" {
		return
	}
	entries := application.loadBlacklist()
	now := time.Now()
	entries[candidate.ID] = blacklistEntry{
		ID: candidate.ID, IP: firstNonEmpty(candidate.IP, candidate.RemoteHost), Country: candidate.Country,
		Reason: reason, MarkedAt: now.Unix(), Until: now.Add(application.config.InvalidBackoff).Unix(),
	}
	_ = writeJSON(filepath.Join(application.config.DataDir, "blacklist.json"), entries)
	_ = application.updateState(func(state *runtimeState) { state.BlacklistedNodes = len(entries) })
	application.logEvent("warning", "VPN", fmt.Sprintf("节点 %s 已加入黑名单: %s", candidate.ID, reason))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
