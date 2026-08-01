package storage

import (
	"errors"

	"github.com/fystack/mpcium-sdk/protocol"
)

var ErrInvalidShareRotation = errors.New("storage: share rotation must contain exactly one of replacement or retire")

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

// ShareRotation is a staged mutation of the active share. Replacement is
// used by new/overlap members; Retire is used by old-only members. Exactly
// one field must be set.
type ShareRotation struct {
	Replacement []byte `json:"replacement,omitempty"`
	Retire      bool   `json:"retire,omitempty"`
}

func (rotation ShareRotation) Validate() error {
	if (len(rotation.Replacement) > 0) == rotation.Retire {
		return ErrInvalidShareRotation
	}
	return nil
}

// ShareRotationStore provides the durable two-phase commit boundary for
// reshare. Implementations must make stage/commit/abort idempotent and the
// active-share replacement or retirement atomic at its storage key.
type ShareRotationStore interface {
	StageShareRotation(protocol protocol.ProtocolType, keyID, sessionID string, rotation ShareRotation) error
	CommitShareRotation(protocol protocol.ProtocolType, keyID, sessionID string) error
	AbortShareRotation(protocol protocol.ProtocolType, keyID, sessionID string) error
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
