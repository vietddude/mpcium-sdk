// In-memory implementations of the SDK's storage interfaces plus the
// identity/lookup types. Copied from the SDK test fixtures — swap these for
// durable stores (badger, files, DB) in production.
package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium-sdk/storage"
)

type testIdentity struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func (t *testIdentity) ParticipantID() string        { return t.id }
func (t *testIdentity) PublicKey() ed25519.PublicKey { return t.pub }
func (t *testIdentity) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(t.priv, message), nil
}

type testPeerLookup struct{ keys map[string]ed25519.PublicKey }

func (l *testPeerLookup) LookupParticipant(participantID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[participantID]
	if !ok {
		return nil, fmt.Errorf("peer %s not found", participantID)
	}
	return key, nil
}

type testOrchestratorLookup struct{ keys map[string]ed25519.PublicKey }

func (l *testOrchestratorLookup) LookupOrchestrator(orchestratorID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[orchestratorID]
	if !ok {
		return nil, fmt.Errorf("orchestrator %s not found", orchestratorID)
	}
	return key, nil
}

type memoryPreparamsStore struct {
	values      map[string][]byte
	activeSlots map[string]string
}

func (s *memoryPreparamsStore) key(protocolType protocol.ProtocolType, slot string) string {
	return string(protocolType) + ":" + slot
}

func (s *memoryPreparamsStore) LoadPreparamsSlot(protocolType protocol.ProtocolType, slot string) ([]byte, error) {
	return append([]byte(nil), s.values[s.key(protocolType, slot)]...), nil
}

func (s *memoryPreparamsStore) SavePreparamsSlot(protocolType protocol.ProtocolType, slot string, preparams []byte) error {
	s.values[s.key(protocolType, slot)] = append([]byte(nil), preparams...)
	return nil
}

func (s *memoryPreparamsStore) LoadActivePreparamsSlot(protocolType protocol.ProtocolType) (string, error) {
	return s.activeSlots[string(protocolType)], nil
}

func (s *memoryPreparamsStore) SaveActivePreparamsSlot(protocolType protocol.ProtocolType, slot string) error {
	s.activeSlots[string(protocolType)] = slot
	return nil
}

type memoryShareStore struct{ values map[string][]byte }

func (s *memoryShareStore) key(protocolType protocol.ProtocolType, keyID string) string {
	return string(protocolType) + ":" + keyID
}

func (s *memoryShareStore) LoadShare(protocolType protocol.ProtocolType, keyID string) ([]byte, error) {
	return append([]byte(nil), s.values[s.key(protocolType, keyID)]...), nil
}

func (s *memoryShareStore) SaveShare(protocolType protocol.ProtocolType, keyID string, share []byte) error {
	s.values[s.key(protocolType, keyID)] = append([]byte(nil), share...)
	return nil
}

// memoryShareRotationStore is the two-phase commit boundary reshare relies on:
// StageShareRotation records the pending replacement/retirement, and
// CommitShareRotation activates it (or deletes the share for retired members).
type memoryShareRotationStore struct {
	shares    *memoryShareStore
	pending   map[string]storage.ShareRotation
	committed map[string]bool
}

func (s *memoryShareRotationStore) rotationKey(protocolType protocol.ProtocolType, keyID, sessionID string) string {
	return string(protocolType) + ":" + keyID + ":" + sessionID
}

func (s *memoryShareRotationStore) StageShareRotation(protocolType protocol.ProtocolType, keyID, sessionID string, rotation storage.ShareRotation) error {
	if err := rotation.Validate(); err != nil {
		return err
	}
	key := s.rotationKey(protocolType, keyID, sessionID)
	if s.committed[key] {
		return nil
	}
	if existing, ok := s.pending[key]; ok {
		if existing.Retire != rotation.Retire || !bytes.Equal(existing.Replacement, rotation.Replacement) {
			return fmt.Errorf("conflicting rotation for %s", key)
		}
		return nil
	}
	rotation.Replacement = append([]byte(nil), rotation.Replacement...)
	s.pending[key] = rotation
	return nil
}

func (s *memoryShareRotationStore) CommitShareRotation(protocolType protocol.ProtocolType, keyID, sessionID string) error {
	key := s.rotationKey(protocolType, keyID, sessionID)
	if s.committed[key] {
		return nil
	}
	rotation, ok := s.pending[key]
	if !ok {
		return fmt.Errorf("rotation %s is not staged", key)
	}
	if rotation.Retire {
		delete(s.shares.values, s.shares.key(protocolType, keyID))
	} else {
		s.shares.values[s.shares.key(protocolType, keyID)] = append([]byte(nil), rotation.Replacement...)
	}
	s.committed[key] = true
	delete(s.pending, key)
	return nil
}

func (s *memoryShareRotationStore) AbortShareRotation(protocolType protocol.ProtocolType, keyID, sessionID string) error {
	key := s.rotationKey(protocolType, keyID, sessionID)
	if s.committed[key] {
		return nil
	}
	delete(s.pending, key)
	return nil
}

type memorySessionCheckpointStore struct{ values map[string][]byte }

func (s *memorySessionCheckpointStore) LoadSessionCheckpoint(sessionID string) ([]byte, error) {
	return append([]byte(nil), s.values[sessionID]...), nil
}

func (s *memorySessionCheckpointStore) SaveSessionCheckpoint(sessionID string, checkpoint []byte) error {
	s.values[sessionID] = append([]byte(nil), checkpoint...)
	return nil
}

func (s *memorySessionCheckpointStore) DeleteSessionCheckpoint(sessionID string) error {
	delete(s.values, sessionID)
	return nil
}
