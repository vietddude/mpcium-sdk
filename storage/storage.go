package storage

import "github.com/fystack/mpcium-sdk/protocol"

type PreparamsStore interface {
	LoadPreparamsSlot(protocol protocol.ProtocolType, slot string) ([]byte, error)
	SavePreparamsSlot(protocol protocol.ProtocolType, slot string, preparams []byte) error
	LoadActivePreparamsSlot(protocol protocol.ProtocolType) (string, error)
	SaveActivePreparamsSlot(protocol protocol.ProtocolType, slot string) error
}

type ShareStore interface {
	LoadShare(protocol protocol.ProtocolType, keyID string) ([]byte, error)
	SaveShare(protocol protocol.ProtocolType, keyID string, share []byte) error
}

// SessionCheckpointStore persists the per-session resume checkpoint — a
// Status snapshot plus the sequence counters and key-exchange progress — so
// an in-flight MPC session can resume across process restarts instead of
// being dropped. The blob is opaque to this layer; the participant package
// owns the encoding.
type SessionCheckpointStore interface {
	LoadSessionCheckpoint(sessionID string) ([]byte, error)
	SaveSessionCheckpoint(sessionID string, checkpoint []byte) error
	DeleteSessionCheckpoint(sessionID string) error
}
