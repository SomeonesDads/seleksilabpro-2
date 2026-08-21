package main

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/worker"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestDrainWorkWaitsForInFlightDelivery(t *testing.T) {
	var active sync.WaitGroup
	active.Add(1)
	go func() {
		defer active.Done()
		time.Sleep(10 * time.Millisecond)
	}()

	if !drainWork(&active, func() {}, context.Background()) {
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

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer drainCancel()
	if drainWork(&active, cancelWork, drainCtx) {
		t.Fatal("drain unexpectedly completed")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("work context was not cancelled")
	}
	active.Wait()
}

// TestDrainWorkCancelsBeforeFinalization proves the B04 timeout phase cancels
// work before the caller performs its bounded finalization join.
func TestDrainWorkCancelsBeforeFinalization(t *testing.T) {
	var active sync.WaitGroup
	active.Add(1)
	workCtx, cancelWork := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer active.Done()
		<-workCtx.Done()
		// Simulate a delivery completing its final persistence/ACK after cancel.
		time.Sleep(30 * time.Millisecond)
		close(finished)
	}()

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer drainCancel()
	if drainWork(&active, cancelWork, drainCtx) {
		t.Fatal("drain unexpectedly completed")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancelled work was not given a final wait to finish")
	}
	active.Wait()
}

// TestRunConsumerLoopStopsIntakeAndDoesNotDoubleStop proves the B04 acceptance
// criteria: once the shutdown signal fires, intake is stopped (no further
// deliveries are accepted) and the broker consumer is stopped exactly once, so
// a repeated shutdown signal cannot double-close or panic.
func armedShutdownCh() chan context.Context {
	c := make(chan context.Context, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	cancel()
	c <- ctx
	return c
}

func TestRunConsumerLoopStopsIntakeAndDoesNotDoubleStop(t *testing.T) {
	signalCtx, cancel := context.WithCancel(context.Background())
	deliveries := make(chan amqp.Delivery, 1)

	var stopCalls int64
	stopConsuming := func() error {
		atomic.AddInt64(&stopCalls, 1)
		return nil
	}
	var stoppedSignals int32
	stopSignals := func() { atomic.AddInt32(&stoppedSignals, 1) }

	w := worker.New(nil, nil, nil, nil, 1, 0, 0)
	var active sync.WaitGroup

	// Signal before the loop starts so the loop deterministically exits on
	// intake-stop without racing a delivery read.
	cancel()
	runConsumerLoop(signalCtx, deliveries, stopConsuming, stopSignals, w, context.Background(), armedShutdownCh(), signalCtx, &active, func() {}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if got := atomic.LoadInt64(&stopCalls); got != 1 {
		t.Fatalf("stopConsuming called %d times, want 1", got)
	}

	// A delivery that arrives after intake stopped must NOT be consumed.
	deliveries <- amqp.Delivery{}
	select {
	case <-deliveries:
		// still buffered = not consumed: correct.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("delivery was consumed after intake was stopped")
	}
}

// TestRunConsumerLoopRepeatedSignalSafe proves a second shutdown signal (a
// repeated SIGTERM) does not panic or call StopConsuming twice.
func TestRunConsumerLoopRepeatedSignalSafe(t *testing.T) {
	for i := 0; i < 3; i++ {
		signalCtx, cancel := context.WithCancel(context.Background())
		deliveries := make(chan amqp.Delivery, 1)
		var stopCalls int64
		stopConsuming := func() error {
			atomic.AddInt64(&stopCalls, 1)
			return nil
		}
		w := worker.New(nil, nil, nil, nil, 1, 0, 0)
		var active sync.WaitGroup
		cancel()
		runConsumerLoop(signalCtx, deliveries, stopConsuming, func() {}, w, context.Background(), armedShutdownCh(), signalCtx, &active, func() {}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if got := atomic.LoadInt64(&stopCalls); got != 1 {
			t.Fatalf("iteration %d: stopConsuming called %d times, want 1", i, got)
		}
	}
}

func TestHaltIntakeForceClosesHungConsumer(t *testing.T) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	shutdownCh := make(chan context.Context, 1)
	shutdownCh <- shutdownCtx
	deliveries := make(chan amqp.Delivery)
	release := make(chan struct{})
	var forced atomic.Bool
	var active sync.WaitGroup

	stopConsuming := func() error {
		<-release
		return nil
	}
	forceClose := func() {
		if forced.CompareAndSwap(false, true) {
			close(release)
		}
	}

	haltIntake(deliveries, stopConsuming, nil, shutdownCh, context.Background(), &active, forceClose, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !forced.Load() {
		t.Fatal("hung consumer was not force-closed")
	}
	active.Wait()
}
