package mobilecore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/vietddude/mpcium-sdk/protocol"
)

type TransportAdapter interface {
	Connect() error
	Subscribe(topic string) error
	Unsubscribe(topic string) error
	Publish(topic string, payloadBase64 string) error
	Read(max int32) string
	Close() error
	ConnectionID() string
}

type nativeRelay struct {
	adapter TransportAdapter

	mu       sync.RWMutex
	handlers map[string][]func([]byte)
}

type incomingTransportMessage struct {
	Topic         string `json:"topic"`
	PayloadBase64 string `json:"payload_base64"`
}

func NewNativeRelay(adapter TransportAdapter) (Relay, error) {
	if adapter == nil {
		return nil, fmt.Errorf("transport adapter is required")
	}
	if err := adapter.Connect(); err != nil {
		return nil, fmt.Errorf("connect transport adapter: %w", err)
	}
	return &nativeRelay{
		adapter:  adapter,
		handlers: map[string][]func([]byte){},
	}, nil
}

func (r *nativeRelay) Subscribe(subject string, handler func([]byte)) (Subscription, error) {
	if handler == nil {
		return nil, fmt.Errorf("handler is required")
	}
	topic := natsToMQTTTopic(subject)

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.handlers[topic]) == 0 {
		if err := r.adapter.Subscribe(topic); err != nil {
			return nil, err
		}
	}
	r.handlers[topic] = append(r.handlers[topic], handler)
	return &nativeSubscription{relay: r, topic: topic}, nil
}

func (r *nativeRelay) Publish(subject string, payload []byte) error {
	topic := natsToMQTTTopic(subject)
	return r.adapter.Publish(topic, base64.StdEncoding.EncodeToString(payload))
}

func (r *nativeRelay) Flush() error {
	return nil
}

func (r *nativeRelay) Poll() error {
	raw := strings.TrimSpace(r.adapter.Read(128))
	if raw == "" || raw == "[]" {
		return nil
	}

	var msgs []incomingTransportMessage
	if err := json.Unmarshal([]byte(raw), &msgs); err != nil {
		return fmt.Errorf("parse transport messages: %w", err)
	}

	for _, msg := range msgs {
		if msg.Topic == "" || msg.PayloadBase64 == "" {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(msg.PayloadBase64)
		if err != nil {
			return fmt.Errorf("decode payload base64: %w", err)
		}

		r.mu.RLock()
		for filter, handlers := range r.handlers {
			if !mqttTopicMatches(filter, msg.Topic) {
				continue
			}
			for _, handler := range handlers {
				handler(append([]byte(nil), payload...))
			}
		}
		r.mu.RUnlock()
	}
	return nil
}

func (r *nativeRelay) Close() {
	_ = r.adapter.Close()
}

func (r *nativeRelay) ConnectionID() string {
	if r == nil || r.adapter == nil {
		return ""
	}
	return r.adapter.ConnectionID()
}

func (r *nativeRelay) ProtocolType() protocol.TransportType {
	return protocol.TransportTypeMQTT
}

type nativeSubscription struct {
	relay *nativeRelay
	topic string
}

func (s *nativeSubscription) Unsubscribe() error {
	if s == nil || s.relay == nil || s.topic == "" {
		return nil
	}

	r := s.relay
	r.mu.Lock()
	defer r.mu.Unlock()

	handlers := r.handlers[s.topic]
	if len(handlers) <= 1 {
		delete(r.handlers, s.topic)
		return r.adapter.Unsubscribe(s.topic)
	}
	r.handlers[s.topic] = handlers[:len(handlers)-1]
	return nil
}

func natsToMQTTTopic(subject string) string {
	replacer := strings.NewReplacer(".", "/", "*", "+")
	return replacer.Replace(subject)
}

func mqttTopicMatches(filter, topic string) bool {
	filterParts := strings.Split(filter, "/")
	topicParts := strings.Split(topic, "/")
	if len(filterParts) != len(topicParts) {
		return false
	}
	for i := range filterParts {
		if filterParts[i] == "+" {
			continue
		}
		if filterParts[i] != topicParts[i] {
			return false
		}
	}
	return true
}
