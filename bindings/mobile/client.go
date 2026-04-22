package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/fystack/mpcium-sdk/bindings/mobile/internal/mobilecore"
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

type StoreAdapter interface {
	Get(key string) string
	Put(key string, valueBase64 string) error
	Delete(key string) error
}

var (
	adapterMu             sync.RWMutex
	registeredTransportAd TransportAdapter
	registeredStoreAd     StoreAdapter
)

func RegisterTransportAdapter(adapter TransportAdapter) error {
	if adapter == nil {
		return fmt.Errorf("transport adapter is required")
	}
	adapterMu.Lock()
	defer adapterMu.Unlock()
	registeredTransportAd = adapter
	return nil
}

func RegisterStoreAdapter(adapter StoreAdapter) error {
	if adapter == nil {
		return fmt.Errorf("store adapter is required")
	}
	adapterMu.Lock()
	defer adapterMu.Unlock()
	registeredStoreAd = adapter
	return nil
}

type Client struct {
	runtime *mobilecore.Runtime

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

type Config struct {
	NodeID                     string          `json:"node_id"`
	DataDir                    string          `json:"data_dir,omitempty"`
	CoordinatorID              string          `json:"coordinator_id"`
	CoordinatorPublicKeyBase64 string          `json:"coordinator_public_key_base64"`
	DBEncryptionKeyBase64      string          `json:"db_encryption_key_base64,omitempty"`
	IdentityPrivateKeyBase64   string          `json:"identity_private_key_base64,omitempty"`
	Transport                  TransportConfig `json:"transport,omitempty"`
	Store                      StoreConfig     `json:"store,omitempty"`
	MQTT                       MQTTConfig      `json:"mqtt,omitempty"`
	MaxActiveSessions          int             `json:"max_active_sessions,omitempty"`
	PresenceIntervalMs         int64           `json:"presence_interval_ms,omitempty"`
	TickIntervalMs             int64           `json:"tick_interval_ms,omitempty"`
	ApprovalTimeoutMs          int64           `json:"approval_timeout_ms,omitempty"`
}

type TransportConfig struct {
	Mode string `json:"mode,omitempty"`
}

type StoreConfig struct {
	Mode string `json:"mode,omitempty"`
}

type MQTTConfig struct {
	Broker   string `json:"broker"`
	ClientID string `json:"client_id"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func NewClient(configJSON string) (*Client, error) {
	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("invalid config JSON: %w", err)
	}

	adapterMu.RLock()
	transportAd := registeredTransportAd
	storeAd := registeredStoreAd
	adapterMu.RUnlock()
	if transportAd == nil {
		return nil, fmt.Errorf("transport adapter is not registered")
	}
	if storeAd == nil {
		return nil, fmt.Errorf("store adapter is not registered")
	}

	relay, err := mobilecore.NewNativeRelay(transportAdapterBridge{ad: transportAd})
	if err != nil {
		return nil, err
	}
	stores, err := mobilecore.NewAdapterStores(storeAdapterBridge{ad: storeAd})
	if err != nil {
		relay.Close()
		return nil, err
	}

	runtimeCfg := mobilecore.Config{
		NodeID:                     cfg.NodeID,
		DataDir:                    cfg.DataDir,
		CoordinatorID:              cfg.CoordinatorID,
		CoordinatorPublicKeyBase64: cfg.CoordinatorPublicKeyBase64,
		DBEncryptionKeyBase64:      cfg.DBEncryptionKeyBase64,
		IdentityPrivateKeyBase64:   cfg.IdentityPrivateKeyBase64,
		Transport: mobilecore.TransportConfig{
			Mode: cfg.Transport.Mode,
		},
		Store: mobilecore.StoreConfig{
			Mode: cfg.Store.Mode,
		},
		MQTT: mobilecore.MQTTConfig{
			Broker:   cfg.MQTT.Broker,
			ClientID: cfg.MQTT.ClientID,
			Username: cfg.MQTT.Username,
			Password: cfg.MQTT.Password,
		},
		MaxActiveSessions: cfg.MaxActiveSessions,
	}
	if cfg.PresenceIntervalMs > 0 {
		runtimeCfg.PresenceInterval = time.Duration(cfg.PresenceIntervalMs) * time.Millisecond
	}
	if cfg.TickIntervalMs > 0 {
		runtimeCfg.TickInterval = time.Duration(cfg.TickIntervalMs) * time.Millisecond
	}
	if cfg.ApprovalTimeoutMs > 0 {
		runtimeCfg.ApprovalTimeout = time.Duration(cfg.ApprovalTimeoutMs) * time.Millisecond
	}

	rt, err := mobilecore.NewRuntime(runtimeCfg, relay, stores)
	if err != nil {
		relay.Close()
		_ = stores.Close()
		return nil, err
	}
	return &Client{runtime: rt}, nil
}

func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.done = make(chan struct{})
	go func() {
		defer close(c.done)
		_ = c.runtime.Run(ctx)
	}()
	return nil
}

func (c *Client) Stop() error {
	c.mu.Lock()
	cancel := c.cancel
	done := c.done
	c.cancel = nil
	c.done = nil
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return c.runtime.Close()
}

func (c *Client) PollEvents(max int32) string {
	if max <= 0 {
		max = 32
	}
	return mobilecore.MarshalEvents(c.runtime.PollEvents(int(max)))
}

func (c *Client) ApproveSign(sessionID string, approved bool, reason string) error {
	return c.runtime.ApproveSign(sessionID, approved, reason)
}

func (c *Client) GetParticipantID() string {
	return c.runtime.ParticipantID()
}

func (c *Client) GetIdentityPublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(c.runtime.IdentityPublicKey())
}

type transportAdapterBridge struct {
	ad TransportAdapter
}

func (b transportAdapterBridge) Connect() error { return b.ad.Connect() }
func (b transportAdapterBridge) Subscribe(topic string) error {
	return b.ad.Subscribe(topic)
}
func (b transportAdapterBridge) Unsubscribe(topic string) error {
	return b.ad.Unsubscribe(topic)
}
func (b transportAdapterBridge) Publish(topic string, payloadBase64 string) error {
	return b.ad.Publish(topic, payloadBase64)
}
func (b transportAdapterBridge) Read(max int32) string { return b.ad.Read(max) }
func (b transportAdapterBridge) Close() error          { return b.ad.Close() }
func (b transportAdapterBridge) ConnectionID() string  { return b.ad.ConnectionID() }

type storeAdapterBridge struct {
	ad StoreAdapter
}

func (b storeAdapterBridge) Get(key string) string {
	return b.ad.Get(key)
}

func (b storeAdapterBridge) Put(key string, valueBase64 string) error {
	return b.ad.Put(key, valueBase64)
}

func (b storeAdapterBridge) Delete(key string) error {
	return b.ad.Delete(key)
}
