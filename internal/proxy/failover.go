package proxy

import (
	"sync"
	"sync/atomic"
	"time"
)

// FailoverTracker 追踪连续出站失败，触发自动切换。
type FailoverTracker struct {
	mu             sync.Mutex
	consecutive    int
	threshold      int
	cooldown       time.Duration
	lastSwitchAt   time.Time
	onTrigger      func(failures int)
	totalFailures  atomic.Int64
	totalSuccesses atomic.Int64
}

// NewFailoverTracker 创建故障切换追踪器。
func NewFailoverTracker(threshold int, cooldown time.Duration, callback func(int)) *FailoverTracker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &FailoverTracker{
		threshold: threshold,
		cooldown:  cooldown,
		onTrigger: callback,
	}
}

// RecordSuccess 记录一次成功连接。
func (ft *FailoverTracker) RecordSuccess() {
	ft.totalSuccesses.Add(1)
	ft.mu.Lock()
	ft.consecutive = 0
	ft.mu.Unlock()
}

// RecordFailure 记录一次失败连接，达到阈值时触发回调。
func (ft *FailoverTracker) RecordFailure() {
	ft.totalFailures.Add(1)
	ft.mu.Lock()
	ft.consecutive++
	shouldTrigger := ft.consecutive >= ft.threshold && time.Since(ft.lastSwitchAt) > ft.cooldown
	if shouldTrigger {
		ft.lastSwitchAt = time.Now()
		ft.consecutive = 0
	}
	failures := ft.consecutive
	callback := ft.onTrigger
	ft.mu.Unlock()
	if shouldTrigger && callback != nil {
		go callback(failures)
	}
}

// Stats 返回故障统计。
func (ft *FailoverTracker) Stats() (failures, successes int64) {
	return ft.totalFailures.Load(), ft.totalSuccesses.Load()
}

// Consecutive 返回当前连续失败次数。
func (ft *FailoverTracker) Consecutive() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.consecutive
}