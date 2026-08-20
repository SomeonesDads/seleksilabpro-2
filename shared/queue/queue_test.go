package queue

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakePublisher struct {
	keys   []string
	bodies [][]byte
	err    error
}

func (p *fakePublisher) Publish(_ context.Context, key string, body []byte) error {
	p.keys = append(p.keys, key)
	p.bodies = append(p.bodies, body)
	return p.err
}

type fakeOutboxStore struct {
	events  []OutboxEvent
	marked  []string
	listErr error
	markErr error
}

func (s *fakeOutboxStore) ListUnpublished(context.Context, int) ([]OutboxEvent, error) {
	return s.events, s.listErr
}

func (s *fakeOutboxStore) MarkPublished(_ context.Context, id string, _ time.Time) error {
	if s.markErr != nil {
		return s.markErr
	}
	s.marked = append(s.marked, id)
	return nil
}

func TestRoutingKeysMatchEventTypes(t *testing.T) {
	for _, eventType := range EventRoutingKeys {
		if RoutingKeyForEvent(eventType) != eventType {
			t.Fatalf("routing key for %q = %q", eventType, RoutingKeyForEvent(eventType))
		}
	}
	if RoutingKeyForEvent("Unknown") != "" || RoutingKeyAll != "#" {
		t.Fatalf("unknown/all routing keys = %q/%q", RoutingKeyForEvent("Unknown"), RoutingKeyAll)
	}
}

func TestMainQueueRoutesPermanentFailuresToDLQ(t *testing.T) {
	args := mainQueueArguments()
	if args["x-dead-letter-exchange"] != "" || args["x-dead-letter-routing-key"] != QueueDLQ {
		t.Fatalf("DLQ arguments = %#v", args)
	}
}

func TestOutboxPublisherPublishesAndMarksOnlySuccessfulEvents(t *testing.T) {
	broker := &fakePublisher{}
	store := &fakeOutboxStore{events: []OutboxEvent{
		{ID: "one", EventType: "SessionRevoked", Payload: []byte(`{"eventType":"SessionRevoked"}`)},
		{ID: "two", EventType: "AccessPolicyChanged", Payload: []byte(`{"eventType":"AccessPolicyChanged"}`)},
	}}
	publisher := NewOutboxPublisher(broker, store, nil, time.Second)

	if err := publisher.PublishBatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(broker.keys) != 2 || broker.keys[0] != "SessionRevoked" || broker.keys[1] != "AccessPolicyChanged" {
		t.Fatalf("published keys = %v", broker.keys)
	}
	if len(store.marked) != 2 || store.marked[0] != "one" || store.marked[1] != "two" {
		t.Fatalf("marked IDs = %v", store.marked)
	}
}

func TestOutboxPublisherLeavesFailedAndUnknownEventsPending(t *testing.T) {
	broker := &fakePublisher{err: errors.New("broker down")}
	store := &fakeOutboxStore{events: []OutboxEvent{
		{ID: "one", EventType: "SessionRevoked", Payload: []byte(`{}`)},
		{ID: "two", EventType: "Unknown", Payload: []byte(`{}`)},
	}}
	publisher := NewOutboxPublisher(broker, store, nil, time.Second)

	if err := publisher.PublishBatch(context.Background()); err == nil {
		t.Fatal("expected publish failure")
	}
	if len(store.marked) != 0 {
		t.Fatalf("failed/unknown events were marked published: %v", store.marked)
	}
}
