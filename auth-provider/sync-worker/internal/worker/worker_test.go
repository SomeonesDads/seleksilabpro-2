package worker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/metrics"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	amqp "github.com/rabbitmq/amqp091-go"
)

type fakeAcknowledger struct {
	acks  int
	nacks []bool
}

func (f *fakeAcknowledger) Ack(uint64, bool) error {
	f.acks++
	return nil
}

func (f *fakeAcknowledger) Nack(_ uint64, _ bool, requeue bool) error {
	f.nacks = append(f.nacks, requeue)
	return nil
}

func (f *fakeAcknowledger) Reject(uint64, bool) error { return nil }

type fakeDeliveryStore struct {
	mu       sync.Mutex
	states   map[string]DeliveryState
	statuses map[string][]string
}

func newFakeDeliveryStore() *fakeDeliveryStore {
	return &fakeDeliveryStore{states: make(map[string]DeliveryState), statuses: make(map[string][]string)}
}

func deliveryKey(eventID, applicationID uuid.UUID) string {
	return eventID.String() + ":" + applicationID.String()
}

func (s *fakeDeliveryStore) BeginDelivery(_ context.Context, eventID, applicationID uuid.UUID) (DeliveryState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := deliveryKey(eventID, applicationID)
	state := s.states[key]
	if state.Status == "succeeded" || state.Status == "failed" {
		return state, nil
	}
	state.AttemptCount++
	state.Status = "processing"
	s.states[key] = state
	s.statuses[key] = append(s.statuses[key], state.Status)
	return state, nil
}

func (s *fakeDeliveryStore) MarkDeliverySucceeded(_ context.Context, eventID, applicationID uuid.UUID, _ time.Time) error {
	return s.mark(eventID, applicationID, "succeeded")
}

func (s *fakeDeliveryStore) MarkDeliveryRetrying(_ context.Context, eventID, applicationID uuid.UUID, _ time.Time, _ error) error {
	return s.mark(eventID, applicationID, "retrying")
}

func (s *fakeDeliveryStore) MarkDeliveryFailed(_ context.Context, eventID, applicationID uuid.UUID, _ time.Time, _ error) error {
	return s.mark(eventID, applicationID, "failed")
}

func (s *fakeDeliveryStore) mark(eventID, applicationID uuid.UUID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := deliveryKey(eventID, applicationID)
	state := s.states[key]
	state.Status = status
	s.states[key] = state
	s.statuses[key] = append(s.statuses[key], status)
	return nil
}

func payloadFor(applicationID *uuid.UUID) EventPayload {
	return EventPayload{
		EventID:          uuid.New(),
		EventType:        "SessionRevoked",
		UserID:           uuid.New(),
		CentralSessionID: uuidPtr(uuid.New()),
		ApplicationID:    applicationID,
		Reason:           "sso_logout",
		OccurredAt:       time.Now().UTC(),
	}
}

func uuidPtr(value uuid.UUID) *uuid.UUID { return &value }

func deliveryFor(t *fakeAcknowledger, payload EventPayload) amqp.Delivery {
	body, _ := json.Marshal(payload)
	return amqp.Delivery{Acknowledger: t, DeliveryTag: 1, Body: body}
}

func TestHandleDeliveryPostsAndSkipsSucceededRedelivery(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.Header.Get("X-Internal-Auth") != "secret" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request = %s %s headers=%v", r.Method, r.URL, r.Header)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	applicationID := uuid.New()
	payload := payloadFor(&applicationID)
	store := newFakeDeliveryStore()
	ack := &fakeAcknowledger{}
	w := New(nil, store, nil, []AppTarget{{ApplicationID: applicationID, LogoutNotifyURL: server.URL, InternalAuthToken: "secret"}}, 2, 0, 0)

	w.HandleDelivery(context.Background(), deliveryFor(ack, payload))
	w.HandleDelivery(context.Background(), deliveryFor(ack, payload))

	if requests != 1 || ack.acks != 2 || len(ack.nacks) != 0 {
		t.Fatalf("requests=%d acks=%d nacks=%v", requests, ack.acks, ack.nacks)
	}
	if state := store.states[deliveryKey(payload.EventID, applicationID)]; state.Status != "succeeded" || state.AttemptCount != 1 {
		t.Fatalf("delivery state = %+v", state)
	}
}

func TestHandleDeliveryRetriesIndependentlyAndDeadLettersPermanentFailure(t *testing.T) {
	var appARequests, appBRequests int
	appA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		appARequests++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer appA.Close()
	appB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		appBRequests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer appB.Close()

	appAID, appBID := uuid.New(), uuid.New()
	payload := payloadFor(nil)
	store := newFakeDeliveryStore()
	ack := &fakeAcknowledger{}
	w := New(nil, store, nil, []AppTarget{
		{ApplicationID: appAID, LogoutNotifyURL: appA.URL, InternalAuthToken: "a-secret"},
		{ApplicationID: appBID, LogoutNotifyURL: appB.URL, InternalAuthToken: "b-secret"},
	}, 2, 0, 0)

	w.HandleDelivery(context.Background(), deliveryFor(ack, payload))

	if appARequests != 2 || appBRequests != 1 || ack.acks != 0 || len(ack.nacks) != 1 || ack.nacks[0] {
		t.Fatalf("A=%d B=%d acks=%d nacks=%v", appARequests, appBRequests, ack.acks, ack.nacks)
	}
	if store.states[deliveryKey(payload.EventID, appAID)].Status != "failed" || store.states[deliveryKey(payload.EventID, appBID)].Status != "succeeded" {
		t.Fatalf("delivery states = %+v", store.states)
	}

	// A redelivery must not ACK an event whose target is already terminally
	// failed; RabbitMQ must keep routing it to the DLQ.
	w.HandleDelivery(context.Background(), deliveryFor(ack, payload))
	if len(ack.nacks) != 2 || ack.nacks[1] {
		t.Fatalf("terminal failure redelivery acknowledgement = %v", ack.nacks)
	}
}

// TestHandleDeliveryInterruptedIsNotFalselyAcked proves the B04 acceptance
// criterion: an interrupted delivery is not falsely marked successful and is
// redelivered (NACK with requeue), never ACKed, when shutdown cancels the work
// context mid-delivery.
func TestHandleDeliveryInterruptedIsNotFalselyAcked(t *testing.T) {
	// A raw listener that accepts the worker's POST but never responds,
	// simulating an unresponsive relying application during shutdown. It
	// releases the accepted connection only once the work context is
	// cancelled, mirroring a delivery cut short by graceful shutdown.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				<-ctx.Done()
				_ = c.Close()
			}(conn)
		}
	}()

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	appAID := uuid.New()
	payload := payloadFor(&appAID)
	store := newFakeDeliveryStore()
	ack := &fakeAcknowledger{}
	w := New(nil, store, nil, []AppTarget{
		{ApplicationID: appAID, LogoutNotifyURL: "http://" + ln.Addr().String() + "/", InternalAuthToken: "secret"},
	}, 5, 0, 0)

	w.HandleDelivery(ctx, deliveryFor(ack, payload))

	if ack.acks != 0 {
		t.Fatalf("interrupted delivery must not be acked, acks=%d", ack.acks)
	}
	if len(ack.nacks) != 1 || !ack.nacks[0] {
		t.Fatalf("interrupted delivery must be nacked for redelivery, nacks=%v", ack.nacks)
	}
	if state := store.states[deliveryKey(payload.EventID, appAID)]; state.Status == "succeeded" {
		t.Fatalf("interrupted delivery must not be marked succeeded: %+v", state)
	}
}

func TestHandleDeliveryMalformedMessageUsesDLQNack(t *testing.T) {
	ack := &fakeAcknowledger{}
	w := New(nil, newFakeDeliveryStore(), nil, nil, 1, 0, 0)
	w.HandleDelivery(context.Background(), amqp.Delivery{Acknowledger: ack, Body: []byte("not-json")})

	if ack.acks != 0 || len(ack.nacks) != 1 || ack.nacks[0] {
		t.Fatalf("acknowledgement = acks:%d nacks:%v", ack.acks, ack.nacks)
	}
}

func TestHandleDeliveryDeadLettersMissingTargetConfiguration(t *testing.T) {
	applicationID := uuid.New()
	ack := &fakeAcknowledger{}
	w := New(nil, newFakeDeliveryStore(), nil, nil, 1, 0, 0)
	w.HandleDelivery(context.Background(), deliveryFor(ack, payloadFor(&applicationID)))

	if ack.acks != 0 || len(ack.nacks) != 1 || ack.nacks[0] {
		t.Fatalf("acknowledgement = acks:%d nacks:%v", ack.acks, ack.nacks)
	}
}

func TestWorkerDeliveryMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	appA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer appA.Close()
	appB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer appB.Close()

	appAID, appBID := uuid.New(), uuid.New()
	payload := payloadFor(nil)
	store := newFakeDeliveryStore()
	ack := &fakeAcknowledger{}
	w := New(nil, store, nil, []AppTarget{
		{ApplicationID: appAID, Name: "app-a", LogoutNotifyURL: appA.URL, InternalAuthToken: "a-secret"},
		{ApplicationID: appBID, Name: "app-b", LogoutNotifyURL: appB.URL, InternalAuthToken: "b-secret"},
	}, 2, 0, 0)
	w.Metrics = m

	w.HandleDelivery(context.Background(), deliveryFor(ack, payload))

	body := gatherMetrics(reg)
	for _, want := range []string{
		"worker_delivery_successes_total 1",
		"worker_delivery_retries_total 1",
		"worker_delivery_permanent_failures_total 1",
		`worker_dlq_total{application="app-a"} 1`,
		`worker_delivery_attempts_total{application="app-a",status="attempt"} 2`,
		`worker_delivery_attempts_total{application="app-b",status="attempt"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q, got:\n%s", want, body)
		}
	}
}

func gatherMetrics(reg *prometheus.Registry) string {
	srv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	buf := make([]byte, 16384)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}
