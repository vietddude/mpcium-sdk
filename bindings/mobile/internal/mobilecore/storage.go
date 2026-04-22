package mobilecore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/fystack/mpcium-sdk/protocol"
)

const (
	identityKey            = "identity:ed25519:private"
	pendingApprovalsIndex  = "approvals:index"
	pendingApprovalKeyPref = "approvals:"
)

type StoreAdapter interface {
	Get(key string) string
	Put(key string, valueBase64 string) error
	Delete(key string) error
}

type Stores interface {
	LoadPreparamsSlot(protocolType protocol.ProtocolType, slot string) ([]byte, error)
	SavePreparamsSlot(protocolType protocol.ProtocolType, slot string, preparams []byte) error
	LoadActivePreparamsSlot(protocolType protocol.ProtocolType) (string, error)
	SaveActivePreparamsSlot(protocolType protocol.ProtocolType, slot string) error

	LoadShare(protocolType protocol.ProtocolType, keyID string) ([]byte, error)
	SaveShare(protocolType protocol.ProtocolType, keyID string, share []byte) error

	LoadSessionCheckpoint(sessionID string) ([]byte, error)
	SaveSessionCheckpoint(sessionID string, checkpoint []byte) error
	DeleteSessionCheckpoint(sessionID string) error

	LoadIdentityPrivateKey() ([]byte, error)
	SaveIdentityPrivateKey(privateKey []byte) error

	LoadPendingSignApproval(sessionID string) ([]byte, error)
	SavePendingSignApproval(sessionID string, blob []byte) error
	DeletePendingSignApproval(sessionID string) error
	ListPendingSignApprovals() (map[string][]byte, error)

	Close() error
}

type adapterStores struct {
	adapter StoreAdapter
}

func NewAdapterStores(adapter StoreAdapter) (Stores, error) {
	if adapter == nil {
		return nil, fmt.Errorf("store adapter is required")
	}
	return &adapterStores{adapter: adapter}, nil
}

func (s *adapterStores) Close() error {
	return nil
}

func (s *adapterStores) LoadPreparamsSlot(protocolType protocol.ProtocolType, slot string) ([]byte, error) {
	return s.load(keyPreparamsSlot(protocolType, slot))
}

func (s *adapterStores) SavePreparamsSlot(protocolType protocol.ProtocolType, slot string, preparams []byte) error {
	return s.save(keyPreparamsSlot(protocolType, slot), preparams)
}

func (s *adapterStores) LoadActivePreparamsSlot(protocolType protocol.ProtocolType) (string, error) {
	value, err := s.load(keyPreparamsActiveSlot(protocolType))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (s *adapterStores) SaveActivePreparamsSlot(protocolType protocol.ProtocolType, slot string) error {
	return s.save(keyPreparamsActiveSlot(protocolType), []byte(slot))
}

func (s *adapterStores) LoadShare(protocolType protocol.ProtocolType, keyID string) ([]byte, error) {
	return s.load(keyShare(protocolType, keyID))
}

func (s *adapterStores) SaveShare(protocolType protocol.ProtocolType, keyID string, share []byte) error {
	return s.save(keyShare(protocolType, keyID), share)
}

func (s *adapterStores) LoadSessionCheckpoint(sessionID string) ([]byte, error) {
	return s.load(keyCheckpoint(sessionID))
}

func (s *adapterStores) SaveSessionCheckpoint(sessionID string, checkpoint []byte) error {
	return s.save(keyCheckpoint(sessionID), checkpoint)
}

func (s *adapterStores) DeleteSessionCheckpoint(sessionID string) error {
	return s.adapter.Delete(keyCheckpoint(sessionID))
}

func (s *adapterStores) LoadIdentityPrivateKey() ([]byte, error) {
	return s.load(identityKey)
}

func (s *adapterStores) SaveIdentityPrivateKey(privateKey []byte) error {
	return s.save(identityKey, privateKey)
}

func (s *adapterStores) LoadPendingSignApproval(sessionID string) ([]byte, error) {
	return s.load(keyPendingApproval(sessionID))
}

func (s *adapterStores) SavePendingSignApproval(sessionID string, blob []byte) error {
	if err := s.save(keyPendingApproval(sessionID), blob); err != nil {
		return err
	}
	ids, err := s.loadPendingApprovalIndex()
	if err != nil {
		return err
	}
	ids[sessionID] = struct{}{}
	return s.savePendingApprovalIndex(ids)
}

func (s *adapterStores) DeletePendingSignApproval(sessionID string) error {
	if err := s.adapter.Delete(keyPendingApproval(sessionID)); err != nil {
		return err
	}
	ids, err := s.loadPendingApprovalIndex()
	if err != nil {
		return err
	}
	delete(ids, sessionID)
	return s.savePendingApprovalIndex(ids)
}

func (s *adapterStores) ListPendingSignApprovals() (map[string][]byte, error) {
	ids, err := s.loadPendingApprovalIndex()
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(ids))
	for sessionID := range ids {
		blob, err := s.LoadPendingSignApproval(sessionID)
		if err != nil {
			return nil, err
		}
		if len(blob) == 0 {
			continue
		}
		out[sessionID] = blob
	}
	return out, nil
}

func (s *adapterStores) load(key string) ([]byte, error) {
	raw := s.adapter.Get(key)
	if raw == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode store value key=%s: %w", key, err)
	}
	return decoded, nil
}

func (s *adapterStores) save(key string, value []byte) error {
	return s.adapter.Put(key, base64.StdEncoding.EncodeToString(value))
}

func keyPreparamsSlot(protocolType protocol.ProtocolType, slot string) string {
	return fmt.Sprintf("preparams:%s:%s", protocolType, slot)
}

func keyPreparamsActiveSlot(protocolType protocol.ProtocolType) string {
	return fmt.Sprintf("preparams:%s:active_slot", protocolType)
}

func keyShare(protocolType protocol.ProtocolType, keyID string) string {
	return fmt.Sprintf("shares:%s:%s", protocolType, keyID)
}

func keyCheckpoint(sessionID string) string {
	return "checkpoints:" + sessionID
}

func keyPendingApproval(sessionID string) string {
	return pendingApprovalKeyPref + sessionID
}

func (s *adapterStores) loadPendingApprovalIndex() (map[string]struct{}, error) {
	blob, err := s.load(pendingApprovalsIndex)
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return map[string]struct{}{}, nil
	}
	var ids []string
	if err := json.Unmarshal(blob, &ids); err != nil {
		return nil, fmt.Errorf("decode pending approval index: %w", err)
	}
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		out[id] = struct{}{}
	}
	return out, nil
}

func (s *adapterStores) savePendingApprovalIndex(ids map[string]struct{}) error {
	flat := make([]string, 0, len(ids))
	for id := range ids {
		flat = append(flat, id)
	}
	sort.Strings(flat)
	blob, err := json.Marshal(flat)
	if err != nil {
		return err
	}
	return s.save(pendingApprovalsIndex, blob)
}
