package mobile

import (
	"encoding/base64"
	"testing"
)

type testTransportAdapter struct{}

func (testTransportAdapter) Connect() error                                   { return nil }
func (testTransportAdapter) Subscribe(topic string) error                     { return nil }
func (testTransportAdapter) Unsubscribe(topic string) error                   { return nil }
func (testTransportAdapter) Publish(topic string, payloadBase64 string) error { return nil }
func (testTransportAdapter) Read(max int32) string                            { return "[]" }
func (testTransportAdapter) Close() error                                     { return nil }
func (testTransportAdapter) ConnectionID() string                             { return "test-conn" }

type testStoreAdapter struct {
	kv map[string]string
}

func (s *testStoreAdapter) Get(key string) string {
	if s.kv == nil {
		s.kv = map[string]string{}
	}
	return s.kv[key]
}
func (s *testStoreAdapter) Put(key string, valueBase64 string) error {
	if s.kv == nil {
		s.kv = map[string]string{}
	}
	s.kv[key] = valueBase64
	return nil
}
func (s *testStoreAdapter) Delete(key string) error {
	if s.kv == nil {
		s.kv = map[string]string{}
	}
	delete(s.kv, key)
	return nil
}

func TestNewClientRequiresAdapters(t *testing.T) {
	adapterMu.Lock()
	registeredTransportAd = nil
	registeredStoreAd = nil
	adapterMu.Unlock()

	cfg := `{"node_id":"peer-01","coordinator_id":"coord-01","coordinator_public_key_base64":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`
	_, err := NewClient(cfg)
	if err == nil {
		t.Fatalf("NewClient() expected error when adapters are missing")
	}
}

func TestNewClientWithRegisteredAdapters(t *testing.T) {
	if err := RegisterTransportAdapter(testTransportAdapter{}); err != nil {
		t.Fatalf("RegisterTransportAdapter() error = %v", err)
	}
	if err := RegisterStoreAdapter(&testStoreAdapter{}); err != nil {
		t.Fatalf("RegisterStoreAdapter() error = %v", err)
	}

	cfg := `{"node_id":"peer-01","coordinator_id":"coord-01","coordinator_public_key_base64":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client == nil {
		t.Fatalf("NewClient() returned nil client")
	}
}
