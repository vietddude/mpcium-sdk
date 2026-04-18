package mobilecore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/fystack/mpcium-sdk/participant"
	"github.com/fystack/mpcium-sdk/protocol"
)

func TestHandleControlSignRequiresApproval(t *testing.T) {
	rt, coordinatorPriv := newTestRuntime(t)
	msg := newSignedSignStart(t, coordinatorPriv, rt.cfg.NodeID, rt.cfg.CoordinatorID, rt.identity.PublicKey())

	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := rt.handleControl(raw); err != nil {
		t.Fatalf("handleControl() error = %v", err)
	}

	rt.pendingMu.Lock()
	_, exists := rt.pendingSign[msg.SessionID]
	rt.pendingMu.Unlock()
	if !exists {
		t.Fatalf("pending approval missing for session %s", msg.SessionID)
	}
	if got := len(rt.sessions); got != 0 {
		t.Fatalf("active sessions = %d, want 0", got)
	}

	events := rt.PollEvents(8)
	if len(events) == 0 || events[0].Type != "sign_approval_required" {
		t.Fatalf("events = %+v, want sign_approval_required", events)
	}
}

func TestApproveSignRejectPublishesSessionFailed(t *testing.T) {
	rt, coordinatorPriv := newTestRuntime(t)
	relay := rt.relay.(*fakeRelay)
	msg := newSignedSignStart(t, coordinatorPriv, rt.cfg.NodeID, rt.cfg.CoordinatorID, rt.identity.PublicKey())
	raw, _ := json.Marshal(msg)
	if err := rt.handleControl(raw); err != nil {
		t.Fatalf("handleControl() error = %v", err)
	}

	if err := rt.ApproveSign(msg.SessionID, false, "user rejected"); err != nil {
		t.Fatalf("ApproveSign(false) error = %v", err)
	}

	payloads := relay.published[sessionEventSubject(msg.SessionID)]
	if len(payloads) != 1 {
		t.Fatalf("session event publishes = %d, want 1", len(payloads))
	}
	var event protocol.SessionEvent
	if err := json.Unmarshal(payloads[0], &event); err != nil {
		t.Fatalf("json.Unmarshal(event) error = %v", err)
	}
	if event.SessionFailed == nil || event.SessionFailed.Reason != protocol.FailureReasonAborted {
		t.Fatalf("session failed event = %+v, want aborted", event.SessionFailed)
	}
}

func TestApproveSignStartsSessionAndPublishesReadyEvents(t *testing.T) {
	rt, coordinatorPriv := newTestRuntime(t)
	relay := rt.relay.(*fakeRelay)
	msg := newSignedSignStart(t, coordinatorPriv, rt.cfg.NodeID, rt.cfg.CoordinatorID, rt.identity.PublicKey())
	raw, _ := json.Marshal(msg)
	if err := rt.handleControl(raw); err != nil {
		t.Fatalf("handleControl() error = %v", err)
	}

	if err := rt.ApproveSign(msg.SessionID, true, ""); err != nil {
		t.Fatalf("ApproveSign(true) error = %v", err)
	}
	if rt.getSession(msg.SessionID) == nil {
		t.Fatalf("session %s not started", msg.SessionID)
	}
	payloads := relay.published[sessionEventSubject(msg.SessionID)]
	if len(payloads) < 2 {
		t.Fatalf("session event publishes = %d, want >= 2", len(payloads))
	}
}

func TestRestorePendingApprovalsEmitsApprovalEvent(t *testing.T) {
	rt, coordinatorPriv := newTestRuntime(t)
	msg := newSignedSignStart(t, coordinatorPriv, rt.cfg.NodeID, rt.cfg.CoordinatorID, rt.identity.PublicKey())
	if err := rt.savePendingApproval(msg); err != nil {
		t.Fatalf("savePendingApproval() error = %v", err)
	}

	rt.pendingMu.Lock()
	rt.pendingSign = map[string]pendingApproval{}
	rt.pendingMu.Unlock()

	if err := rt.restorePendingApprovals(); err != nil {
		t.Fatalf("restorePendingApprovals() error = %v", err)
	}

	rt.pendingMu.Lock()
	_, exists := rt.pendingSign[msg.SessionID]
	rt.pendingMu.Unlock()
	if !exists {
		t.Fatalf("pending approval missing after restore")
	}
	events := rt.PollEvents(16)
	found := false
	for _, e := range events {
		if e.Type == "sign_approval_required" && e.SessionID == msg.SessionID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("events=%+v, want sign_approval_required for restored session", events)
	}
}

func newTestRuntime(t *testing.T) (*Runtime, ed25519.PrivateKey) {
	t.Helper()
	coordinatorPub, coordinatorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(coordinator) error = %v", err)
	}
	localPub, localPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(local) error = %v", err)
	}
	identity, err := newLocalIdentity("peer-mobile-01", localPriv)
	if err != nil {
		t.Fatalf("newLocalIdentity() error = %v", err)
	}
	coordLookup, err := newCoordinatorLookup("coordinator-01", coordinatorPub)
	if err != nil {
		t.Fatalf("newCoordinatorLookup() error = %v", err)
	}
	_ = localPub
	return &Runtime{
		cfg: Config{
			NodeID:            "peer-mobile-01",
			CoordinatorID:     "coordinator-01",
			MaxActiveSessions: 5,
			ApprovalTimeout:   DefaultApprovalTimeout,
		},
		relay:       newFakeRelay(),
		stores:      newMemoryStores(),
		identity:    identity,
		coordLookup: coordLookup,
		sessions:    map[string]*participant.ParticipantSession{},
		sessionMeta: map[string]string{},
		sessionSeq:  map[string]uint64{},
		pendingSign: map[string]pendingApproval{},
	}, coordinatorPriv
}

func newSignedSignStart(t *testing.T, coordinatorPriv ed25519.PrivateKey, localID, coordinatorID string, localPub []byte) *protocol.ControlMessage {
	t.Helper()
	peerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(peer) error = %v", err)
	}
	msg := &protocol.ControlMessage{
		SessionID:     "sess-sign-approval",
		Sequence:      1,
		CoordinatorID: coordinatorID,
		SessionStart: &protocol.SessionStart{
			SessionID: "sess-sign-approval",
			Protocol:  protocol.ProtocolTypeECDSA,
			Operation: protocol.OperationTypeSign,
			Threshold: 1,
			Participants: []*protocol.SessionParticipant{
				{ParticipantID: localID, PartyKey: []byte(localID), IdentityPublicKey: localPub},
				{ParticipantID: "peer-node-02", PartyKey: []byte("peer-node-02"), IdentityPublicKey: peerPub},
			},
			Sign: &protocol.SignPayload{
				KeyID:        "wallet-key",
				SigningInput: []byte("0xabc"),
			},
		},
	}
	signingBytes, err := protocol.ControlSigningBytes(msg)
	if err != nil {
		t.Fatalf("ControlSigningBytes() error = %v", err)
	}
	msg.Signature = ed25519.Sign(coordinatorPriv, signingBytes)
	return msg
}

type fakeRelay struct {
	published map[string][][]byte
}

func newFakeRelay() *fakeRelay {
	return &fakeRelay{published: map[string][][]byte{}}
}

func (r *fakeRelay) Subscribe(_ string, _ func([]byte)) (Subscription, error) {
	return fakeSubscription{}, nil
}

func (r *fakeRelay) Publish(subject string, payload []byte) error {
	r.published[subject] = append(r.published[subject], append([]byte(nil), payload...))
	return nil
}

func (r *fakeRelay) Flush() error { return nil }
func (r *fakeRelay) Poll() error  { return nil }
func (r *fakeRelay) Close()       {}
func (r *fakeRelay) ConnectionID() string {
	return "test-connection-id"
}
func (r *fakeRelay) ProtocolType() protocol.TransportType {
	return protocol.TransportTypeMQTT
}

type fakeSubscription struct{}

func (fakeSubscription) Unsubscribe() error { return nil }

type memoryStores struct {
	values       map[string][]byte
	activeSlots  map[string]string
	shares       map[string][]byte
	artifacts    map[string][]byte
	identityPriv []byte
	pending      map[string][]byte
}

func newMemoryStores() *memoryStores {
	return &memoryStores{
		values:      map[string][]byte{},
		activeSlots: map[string]string{},
		shares:      map[string][]byte{},
		artifacts:   map[string][]byte{},
		pending:     map[string][]byte{},
	}
}

func (m *memoryStores) LoadPreparamsSlot(protocolType protocol.ProtocolType, slot string) ([]byte, error) {
	return append([]byte(nil), m.values[m.ppKey(protocolType, slot)]...), nil
}
func (m *memoryStores) SavePreparamsSlot(protocolType protocol.ProtocolType, slot string, preparams []byte) error {
	m.values[m.ppKey(protocolType, slot)] = append([]byte(nil), preparams...)
	return nil
}
func (m *memoryStores) LoadActivePreparamsSlot(protocolType protocol.ProtocolType) (string, error) {
	return m.activeSlots[string(protocolType)], nil
}
func (m *memoryStores) SaveActivePreparamsSlot(protocolType protocol.ProtocolType, slot string) error {
	m.activeSlots[string(protocolType)] = slot
	return nil
}
func (m *memoryStores) LoadShare(protocolType protocol.ProtocolType, keyID string) ([]byte, error) {
	return append([]byte(nil), m.shares[m.shareKey(protocolType, keyID)]...), nil
}
func (m *memoryStores) SaveShare(protocolType protocol.ProtocolType, keyID string, share []byte) error {
	m.shares[m.shareKey(protocolType, keyID)] = append([]byte(nil), share...)
	return nil
}
func (m *memoryStores) LoadSessionArtifacts(sessionID string) ([]byte, error) {
	return append([]byte(nil), m.artifacts[sessionID]...), nil
}
func (m *memoryStores) SaveSessionArtifacts(sessionID string, artifact []byte) error {
	m.artifacts[sessionID] = append([]byte(nil), artifact...)
	return nil
}
func (m *memoryStores) DeleteSessionArtifacts(sessionID string) error {
	delete(m.artifacts, sessionID)
	return nil
}
func (m *memoryStores) LoadIdentityPrivateKey() ([]byte, error) {
	return append([]byte(nil), m.identityPriv...), nil
}
func (m *memoryStores) SaveIdentityPrivateKey(privateKey []byte) error {
	m.identityPriv = append([]byte(nil), privateKey...)
	return nil
}
func (m *memoryStores) LoadPendingSignApproval(sessionID string) ([]byte, error) {
	return append([]byte(nil), m.pending[sessionID]...), nil
}
func (m *memoryStores) SavePendingSignApproval(sessionID string, blob []byte) error {
	m.pending[sessionID] = append([]byte(nil), blob...)
	return nil
}
func (m *memoryStores) DeletePendingSignApproval(sessionID string) error {
	delete(m.pending, sessionID)
	return nil
}
func (m *memoryStores) ListPendingSignApprovals() (map[string][]byte, error) {
	out := make(map[string][]byte, len(m.pending))
	for k, v := range m.pending {
		out[k] = append([]byte(nil), v...)
	}
	return out, nil
}
func (m *memoryStores) Close() error { return nil }

func (m *memoryStores) ppKey(protocolType protocol.ProtocolType, slot string) string {
	return fmt.Sprintf("%s:%s", protocolType, slot)
}
func (m *memoryStores) shareKey(protocolType protocol.ProtocolType, keyID string) string {
	return fmt.Sprintf("%s:%s", protocolType, keyID)
}
