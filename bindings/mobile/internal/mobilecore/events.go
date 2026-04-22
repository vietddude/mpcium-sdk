package mobilecore

import (
	"encoding/json"
	"sync"
	"time"
)

type RuntimeEvent struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id,omitempty"`
	Operation string `json:"operation,omitempty"`
	Message   string `json:"message,omitempty"`
	Timestamp int64  `json:"timestamp_unix_ms"`
}

func newRuntimeEvent(eventType, sessionID, operation, message string) RuntimeEvent {
	return RuntimeEvent{
		Type:      eventType,
		SessionID: sessionID,
		Operation: operation,
		Message:   message,
		Timestamp: time.Now().UnixMilli(),
	}
}

type eventQueue struct {
	mu     sync.Mutex
	events []RuntimeEvent
}

func (q *eventQueue) push(e RuntimeEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events = append(q.events, e)
}

func (q *eventQueue) popN(max int) []RuntimeEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	if max <= 0 || len(q.events) == 0 {
		return nil
	}
	if max > len(q.events) {
		max = len(q.events)
	}
	out := append([]RuntimeEvent(nil), q.events[:max]...)
	q.events = append([]RuntimeEvent(nil), q.events[max:]...)
	return out
}

func MarshalEvents(events []RuntimeEvent) string {
	if len(events) == 0 {
		return "[]"
	}
	raw, err := json.Marshal(events)
	if err != nil {
		return "[]"
	}
	return string(raw)
}
