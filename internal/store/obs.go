package store

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

var observationMu sync.Mutex

// LogEvent 记录一条结构化日志到控制台和磁盘。
func (s *Store) LogEvent(level, module, message string) {
	entry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), Level: strings.ToUpper(level), Module: module, Message: message}
	fmt.Printf("[%s] [%s] %s\n", entry.Level, entry.Module, entry.Message)
	observationMu.Lock()
	defer observationMu.Unlock()
	logsDir := filepath.Join(s.Config.DataDir, "logs")
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
	s.cleanupLogs(logsDir)
}

func (s *Store) cleanupLogs(logsDir string) {
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

// RecentLogs 返回最近 limit 条日志。
func (s *Store) RecentLogs(limit int) []LogEntry {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	observationMu.Lock()
	defer observationMu.Unlock()
	today := time.Now().Format("2006-01-02")
	names := []string{today + ".json", today + ".jsonl"}
	result := make([]LogEntry, 0, limit)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(s.Config.DataDir, "logs", name))
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			var entry LogEntry
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

// LoadBlacklist 读取并清理过期黑名单条目。
func (s *Store) LoadBlacklist() map[string]BlacklistEntry {
	entries := map[string]BlacklistEntry{}
	_ = readJSON(filepath.Join(s.Config.DataDir, "blacklist.json"), &entries)
	now := time.Now().Unix()
	changed := false
	for id, entry := range entries {
		if entry.Until <= now {
			delete(entries, id)
			changed = true
		}
	}
	if changed {
		_ = writeJSON(filepath.Join(s.Config.DataDir, "blacklist.json"), entries)
	}
	return entries
}

// MarkBlacklisted 将一个节点加入黑名单。
func (s *Store) MarkBlacklisted(candidate Node, reason string) {
	if candidate.ID == "" {
		return
	}
	entries := s.LoadBlacklist()
	now := time.Now()
	entries[candidate.ID] = BlacklistEntry{
		ID: candidate.ID, IP: FirstNonEmpty(candidate.IP, candidate.RemoteHost), Country: candidate.Country,
		Reason: reason, MarkedAt: now.Unix(), Until: now.Add(s.Config.InvalidBackoff).Unix(),
	}
	_ = writeJSON(filepath.Join(s.Config.DataDir, "blacklist.json"), entries)
	_ = s.UpdateState(func(state *RuntimeState) { state.BlacklistedNodes = len(entries) })
	s.LogEvent("warning", "VPN", fmt.Sprintf("节点 %s 已加入黑名单: %s", candidate.ID, reason))
}

// FirstNonEmpty 返回第一个非空字符串。
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
