package mobilecore

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

const (
	DefaultMaxActiveSessions = 5
	DefaultPresenceInterval  = 5 * time.Second
	DefaultTickInterval      = 100 * time.Millisecond
	DefaultApprovalTimeout   = 60 * time.Second
)

type Config struct {
	NodeID                     string
	DataDir                    string
	CoordinatorID              string
	CoordinatorPublicKeyBase64 string
	DBEncryptionKeyBase64      string
	IdentityPrivateKeyBase64   string
	Transport                  TransportConfig
	Store                      StoreConfig
	MQTT                       MQTTConfig
	MaxActiveSessions          int
	PresenceInterval           time.Duration
	TickInterval               time.Duration
	ApprovalTimeout            time.Duration
}

type TransportConfig struct {
	Mode string
}

type StoreConfig struct {
	Mode string
}

const (
	TransportModeNative = "native"
	StoreModeNative     = "native"
)

type MQTTConfig struct {
	Broker   string
	ClientID string
	Username string
	Password string
}

func (c *Config) applyDefaults() {
	c.NodeID = strings.TrimSpace(c.NodeID)
	c.DataDir = strings.TrimSpace(c.DataDir)
	c.CoordinatorID = strings.TrimSpace(c.CoordinatorID)
	c.CoordinatorPublicKeyBase64 = strings.TrimSpace(c.CoordinatorPublicKeyBase64)
	c.DBEncryptionKeyBase64 = strings.TrimSpace(c.DBEncryptionKeyBase64)
	c.IdentityPrivateKeyBase64 = strings.TrimSpace(c.IdentityPrivateKeyBase64)
	c.Transport.Mode = strings.TrimSpace(strings.ToLower(c.Transport.Mode))
	c.Store.Mode = strings.TrimSpace(strings.ToLower(c.Store.Mode))
	c.MQTT.Broker = strings.TrimSpace(c.MQTT.Broker)
	c.MQTT.ClientID = strings.TrimSpace(c.MQTT.ClientID)
	c.MQTT.Username = strings.TrimSpace(c.MQTT.Username)
	c.MQTT.Password = strings.TrimSpace(c.MQTT.Password)

	if c.Transport.Mode == "" {
		c.Transport.Mode = TransportModeNative
	}
	if c.Store.Mode == "" {
		c.Store.Mode = StoreModeNative
	}

	if c.MaxActiveSessions <= 0 {
		c.MaxActiveSessions = DefaultMaxActiveSessions
	}
	if c.PresenceInterval <= 0 {
		c.PresenceInterval = DefaultPresenceInterval
	}
	if c.TickInterval <= 0 {
		c.TickInterval = DefaultTickInterval
	}
	if c.ApprovalTimeout <= 0 {
		c.ApprovalTimeout = DefaultApprovalTimeout
	}
}

func (c *Config) Validate() error {
	c.applyDefaults()
	if c.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}
	if c.CoordinatorID == "" {
		return fmt.Errorf("coordinator_id is required")
	}
	if c.CoordinatorPublicKeyBase64 == "" {
		return fmt.Errorf("coordinator_public_key_base64 is required")
	}
	if c.Transport.Mode != TransportModeNative {
		return fmt.Errorf("unsupported transport.mode %q", c.Transport.Mode)
	}
	if c.Store.Mode != StoreModeNative {
		return fmt.Errorf("unsupported store.mode %q", c.Store.Mode)
	}
	return nil
}

func (c Config) CoordinatorPublicKeyBytes() ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(c.CoordinatorPublicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode coordinator_public_key_base64: %w", err)
	}
	return decoded, nil
}

func (c Config) DBEncryptionKeyBytes() ([]byte, error) {
	if c.DBEncryptionKeyBase64 == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(c.DBEncryptionKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode db_encryption_key_base64: %w", err)
	}
	if n := len(decoded); n != 16 && n != 24 && n != 32 {
		return nil, fmt.Errorf("db encryption key must be 16, 24, or 32 bytes")
	}
	return decoded, nil
}

func (c Config) IdentityPrivateKeyBytes() ([]byte, error) {
	if c.IdentityPrivateKeyBase64 == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(c.IdentityPrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode identity_private_key_base64: %w", err)
	}
	return decoded, nil
}
