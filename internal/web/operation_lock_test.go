package web

import (
	"sync"
	"testing"
	"time"
)

func TestOperationLockUnlockIfOwned(t *testing.T) {
	var lock operationLock
	if !lock.TryLock() {
		t.Fatal("expected fresh lock to be acquirable")
	}
	lock.unlockIfOwned()
	if !lock.TryLock() {
		t.Fatal("expected lock to be released by owner")
	}
	lock.Unlock()
}

func TestOperationLockUnlockIfOwnedIgnoresOtherOwner(t *testing.T) {
	var lock operationLock
	if !lock.TryLock() {
		t.Fatal("expected fresh lock to be acquirable")
	}
	released := make(chan struct{})
	go func() {
		lock.unlockIfOwned()
		close(released)
	}()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("unlockIfOwned should not block")
	}
	if lock.TryLock() {
		t.Fatal("other goroutine must not release a lock it does not own")
	}
	lock.Unlock() //nolint:sync // test recovers from intentionally leaked lock
}

func TestOperationLockForceUnlockIfStale(t *testing.T) {
	var lock operationLock
	if !lock.TryLock() {
		t.Fatal("expected fresh lock to be acquirable")
	}
	previous := operationLockTimeout
	defer func() { operationLockTimeout = previous }()
	operationLockTimeout = 50 * time.Millisecond
	lock.owner.Store(time.Now().Add(-time.Hour).UnixNano())
	recoveryOwner := int64(goroutineID()) + 1
	if !lock.forceUnlockIfStaleWithOwner(recoveryOwner) {
		t.Fatal("expected stale lock to be force unlocked")
	}
	if lock.owner.Load() != recoveryOwner {
		t.Fatalf("expected recovery owner to be recorded, got %d", lock.owner.Load())
	}
	if !lock.mutex.TryLock() {
		t.Fatal("expected lock to be acquirable after stale recovery")
	}
	lock.owner.Store(0)
	lock.mutex.Unlock()
}

func TestOperationLockConcurrentOwnership(t *testing.T) {
	var lock operationLock
	var waitGroup sync.WaitGroup
	for index := 0; index < 8; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for attempt := 0; attempt < 20; attempt++ {
				if lock.TryLock() {
					lock.unlockIfOwned()
				}
			}
		}()
	}
	waitGroup.Wait()
	if !lock.TryLock() {
		t.Fatal("expected lock to be free after concurrent use")
	}
	lock.Unlock()
}
