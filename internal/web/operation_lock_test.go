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

func TestOperationLockCanBeReleasedByWorker(t *testing.T) {
	var lock operationLock
	if !lock.TryLock() {
		t.Fatal("expected fresh lock to be acquirable")
	}
	released := make(chan struct{})
	go func() {
		lock.unlockIfOwned()
		close(released)
	}()
	<-released
	if !lock.TryLock() {
		t.Fatal("expected worker to release the operation lock")
	}
	lock.Unlock()
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

func TestOperationLockTryLockForWaitsForRelease(t *testing.T) {
	var lock operationLock
	if !lock.TryLock() {
		t.Fatal("expected fresh lock to be acquirable")
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		lock.Unlock()
	}()
	if !lock.TryLockFor(time.Second) {
		t.Fatal("expected timed lock to acquire after maintenance releases it")
	}
	lock.Unlock()
}

func TestOperationLockTryLockForTimesOut(t *testing.T) {
	var lock operationLock
	if !lock.TryLock() {
		t.Fatal("expected fresh lock to be acquirable")
	}
	if lock.TryLockFor(100 * time.Millisecond) {
		t.Fatal("expected timed lock to fail while lock stays held")
	}
	lock.Unlock()
}
