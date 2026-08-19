package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDrainWorkWaitsForInFlightDelivery(t *testing.T) {
	var active sync.WaitGroup
	active.Add(1)
	go func() {
		defer active.Done()
		time.Sleep(10 * time.Millisecond)
	}()

	if !drainWork(&active, func() {}, 100*time.Millisecond) {
		t.Fatal("drain timed out before work completed")
	}
}

func TestDrainWorkCancelsAfterTimeout(t *testing.T) {
	var active sync.WaitGroup
	active.Add(1)
	workCtx, cancelWork := context.WithCancel(context.Background())
	defer cancelWork()
	finished := make(chan struct{})
	go func() {
		defer active.Done()
		<-workCtx.Done()
		close(finished)
	}()

	if drainWork(&active, cancelWork, 10*time.Millisecond) {
		t.Fatal("drain unexpectedly completed")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("work context was not cancelled")
	}
	active.Wait()
}
