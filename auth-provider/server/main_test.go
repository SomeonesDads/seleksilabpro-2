package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestServeDrainsInFlightRequest proves the B04 acceptance criterion: a
// long-running HTTP request completes before shutdown returns when it finishes
// within the configured timeout.
func TestServeDrainsInFlightRequest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	started := make(chan struct{})
	done := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		close(done)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeAddr(t)
	gs := newGracefulServer(addr, handler)
	gs.run(logger)
	serveDone := make(chan struct{})
	go func() {
		_, _ = gs.shutdown(ctx, 2*time.Second, logger)
		close(serveDone)
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	var resp *http.Response
	var err error
	for i := 0; i < 100; i++ {
		resp, err = client.Get("http://" + addr + "/")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect to server: %v", err)
	}
	_ = resp.Body.Close()

	<-started // handler is mid-request
	cancel()  // trigger shutdown while the request is in flight
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not complete before shutdown returned")
	}
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after draining")
	}
}

// TestServeTimesOutWhenRequestHangs proves the B04 acceptance criterion:
// shutdown completes within the configured timeout even when a dependency (the
// request handler) hangs, rather than blocking process exit indefinitely.
func TestServeTimesOutWhenRequestHangs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var once sync.Once
	started := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done() // hold until the server connection is closed
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeAddr(t)
	gs := newGracefulServer(addr, handler)
	gs.run(logger)
	serveDone := make(chan struct{})
	go func() {
		_, _ = gs.shutdown(ctx, 100*time.Millisecond, logger)
		close(serveDone)
	}()

	// Drive one request that reaches the handler; the handler blocks until the
	// work context is cancelled, so we retry quickly until it has started.
	go func() {
		for {
			select {
			case <-started:
				return
			default:
			}
			client := &http.Client{Timeout: 150 * time.Millisecond}
			_, _ = client.Get("http://" + addr + "/")
		}
	}()

	<-started
	cancel()

	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not complete within the timeout")
	}
}

func TestShutdownReportsHandlerThatIgnoresCancellation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	release := make(chan struct{})
	finished := make(chan struct{})
	gs := newGracefulServer(freeAddr(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	gs.wg.Add(1)
	go func() {
		defer gs.wg.Done()
		<-release
		close(finished)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	shutdownDone := make(chan bool, 1)
	go func() {
		drained, _ := gs.shutdown(ctx, 100*time.Millisecond, logger)
		shutdownDone <- drained
	}()
	cancel()

	select {
	case drained := <-shutdownDone:
		if drained {
			t.Fatal("shutdown reported drained while handler ignored cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not honor hard deadline")
	}

	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("test handler did not finish after release")
	}
}
