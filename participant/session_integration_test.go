package participant

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/vietddude/mpcium-sdk/protocol"
)

func TestSessionECDSAKeygenAndSign(t *testing.T) {
	participants, coordinator, err := newTestParticipants(3)
	if err != nil {
		t.Fatalf("newTestParticipants() error = %v", err)
	}
	fixtureKeys, _, err := ecdsaKeygen.LoadKeygenTestFixtures(3)
	if err != nil {
		t.Fatalf("LoadKeygenTestFixtures() error = %v", err)
	}

	keygenStart := &protocol.SessionStart{
		SessionID: "session-ecdsa-keygen",
		Protocol:  protocol.ProtocolTypeECDSA,
		Operation: protocol.OperationTypeKeygen,
		Threshold: 1,
		Participants: []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.ParticipantID(), PartyKey: []byte{1}, IdentityPublicKey: participants[0].id.pub},
			{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte{2}, IdentityPublicKey: participants[1].id.pub},
			{ParticipantID: participants[2].id.ParticipantID(), PartyKey: []byte{3}, IdentityPublicKey: participants[2].id.pub},
		},
		Keygen: &protocol.KeygenPayload{KeyID: "ecdsa-key"},
	}

	for i := range participants {
		blob, encodeErr := encodeECDSAPreparams(&fixtureKeys[i].LocalPreParams)
		if encodeErr != nil {
			t.Fatalf("encodeECDSAPreparams() error = %v", encodeErr)
		}
		if saveErr := participants[i].preparams.SavePreparams(protocol.ProtocolTypeECDSA, "ecdsa-key", blob); saveErr != nil {
			t.Fatalf("SavePreparams() error = %v", saveErr)
		}
	}

	sessions := createSessions(t, keygenStart, participants, coordinator)
	keygenResults := driveSession(t, keygenStart.SessionID, sessions, coordinator)
	for id, result := range keygenResults {
		if result == nil || result.KeyShare == nil || len(result.KeyShare.ShareBlob) == 0 {
			t.Fatalf("keygen result missing share blob for %s", id)
		}
	}

	signStart := &protocol.SessionStart{
		SessionID: "session-ecdsa-sign",
		Protocol:  protocol.ProtocolTypeECDSA,
		Operation: protocol.OperationTypeSign,
		Threshold: 1,
		Participants: []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.ParticipantID(), PartyKey: []byte{1}, IdentityPublicKey: participants[0].id.pub},
			{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte{2}, IdentityPublicKey: participants[1].id.pub},
			{ParticipantID: participants[2].id.ParticipantID(), PartyKey: []byte{3}, IdentityPublicKey: participants[2].id.pub},
		},
		Sign: &protocol.SignPayload{KeyID: "ecdsa-key", SigningInput: []byte("ecdsa-message")},
	}

	signSessions := createSessions(t, signStart, participants, coordinator)
	signResults := driveSession(t, signStart.SessionID, signSessions, coordinator)
	for id, result := range signResults {
		if result == nil || result.Signature == nil || len(result.Signature.Signature) == 0 {
			t.Fatalf("sign result missing signature for %s", id)
		}
	}
}

func TestSessionEdDSAKeygenAndSign(t *testing.T) {
	participants, coordinator, err := newTestParticipants(3)
	if err != nil {
		t.Fatalf("newTestParticipants() error = %v", err)
	}

	keygenStart := &protocol.SessionStart{
		SessionID: "session-eddsa-keygen",
		Protocol:  protocol.ProtocolTypeEdDSA,
		Operation: protocol.OperationTypeKeygen,
		Threshold: 1,
		Participants: []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.ParticipantID(), PartyKey: []byte{1}, IdentityPublicKey: participants[0].id.pub},
			{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte{2}, IdentityPublicKey: participants[1].id.pub},
			{ParticipantID: participants[2].id.ParticipantID(), PartyKey: []byte{3}, IdentityPublicKey: participants[2].id.pub},
		},
		Keygen: &protocol.KeygenPayload{KeyID: "eddsa-key"},
	}

	sessions := createSessions(t, keygenStart, participants, coordinator)
	keygenResults := driveSession(t, keygenStart.SessionID, sessions, coordinator)
	for id, result := range keygenResults {
		if result == nil || result.KeyShare == nil || len(result.KeyShare.ShareBlob) == 0 {
			t.Fatalf("keygen result missing share blob for %s", id)
		}
	}

	signStart := &protocol.SessionStart{
		SessionID: "session-eddsa-sign",
		Protocol:  protocol.ProtocolTypeEdDSA,
		Operation: protocol.OperationTypeSign,
		Threshold: 1,
		Participants: []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.ParticipantID(), PartyKey: []byte{1}, IdentityPublicKey: participants[0].id.pub},
			{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte{2}, IdentityPublicKey: participants[1].id.pub},
			{ParticipantID: participants[2].id.ParticipantID(), PartyKey: []byte{3}, IdentityPublicKey: participants[2].id.pub},
		},
		Sign: &protocol.SignPayload{KeyID: "eddsa-key", SigningInput: []byte("eddsa-message")},
	}

	signSessions := createSessions(t, signStart, participants, coordinator)
	signResults := driveSession(t, signStart.SessionID, signSessions, coordinator)
	for id, result := range signResults {
		if result == nil || result.Signature == nil || len(result.Signature.Signature) == 0 {
			t.Fatalf("sign result missing signature for %s", id)
		}
	}
}

func TestSessionRejectsMPCBeginBeforeKeyExchange(t *testing.T) {
	participants, coordinator, err := newTestParticipants(2)
	if err != nil {
		t.Fatalf("newTestParticipants() error = %v", err)
	}
	start := &protocol.SessionStart{
		SessionID: "session-missing-kx",
		Protocol:  protocol.ProtocolTypeECDSA,
		Operation: protocol.OperationTypeKeygen,
		Threshold: 1,
		Participants: []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.ParticipantID(), PartyKey: []byte{1}, IdentityPublicKey: participants[0].id.pub},
			{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte{2}, IdentityPublicKey: participants[1].id.pub},
		},
		Keygen: &protocol.KeygenPayload{KeyID: "k"},
	}
	session := createSessions(t, start, participants[:1], coordinator)[participants[0].id.id]
	if _, err := session.Start(); err != nil {
		t.Fatalf("Session.Start() error = %v", err)
	}
	ctrl := &protocol.ControlMessage{
		SessionID:     start.SessionID,
		Sequence:      1,
		CoordinatorID: coordinator.id,
		MPCBegin:      &protocol.MPCBegin{},
	}
	ctrl.Signature = ed25519.Sign(coordinator.priv, protocol.MustControlSigningBytes(ctrl))
	if _, err := session.HandleControl(ctrl); err != ErrKeyExchangeRequired {
		t.Fatalf("HandleControl(MPCBegin) error = %v, want %v", err, ErrKeyExchangeRequired)
	}
}

type participantFixture struct {
	id        *testIdentity
	lookup    *testPeerLookup
	preparams *memoryPreparamsStore
	shares    *memoryShareStore
	artifacts *memorySessionArtifactsStore
}

type coordinatorFixture struct {
	id     string
	priv   ed25519.PrivateKey
	lookup *testCoordinatorLookup
}

type queuedMessage struct {
	sender string
	msg    *protocol.PeerMessage
}

func newTestParticipants(count int) ([]participantFixture, coordinatorFixture, error) {
	peerLookup := &testPeerLookup{keys: make(map[string]ed25519.PublicKey, count)}
	fixtures := make([]participantFixture, 0, count)
	for i := 0; i < count; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, coordinatorFixture{}, err
		}
		identity := &testIdentity{id: fmt.Sprintf("peer-%d", i+1), pub: pub, priv: priv}
		peerLookup.keys[identity.id] = pub
		fixtures = append(fixtures, participantFixture{
			id:        identity,
			lookup:    peerLookup,
			preparams: &memoryPreparamsStore{values: map[string][]byte{}},
			shares:    &memoryShareStore{values: map[string][]byte{}},
			artifacts: &memorySessionArtifactsStore{values: map[string][]byte{}},
		})
	}
	coordinatorPub, coordinatorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, coordinatorFixture{}, err
	}
	coordinatorLookup := &testCoordinatorLookup{keys: map[string]ed25519.PublicKey{"coordinator-1": coordinatorPub}}
	return fixtures, coordinatorFixture{id: "coordinator-1", priv: coordinatorPriv, lookup: coordinatorLookup}, nil
}

func createSessions(t *testing.T, start *protocol.SessionStart, fixtures []participantFixture, coordinator coordinatorFixture) map[string]*ParticipantSession {
	t.Helper()
	sessions := make(map[string]*ParticipantSession, len(fixtures))
	for _, fixture := range fixtures {
		session, err := New(Config{
			Start:              start,
			LocalParticipantID: fixture.id.id,
			Identity:           fixture.id,
			Peers:              fixture.lookup,
			Coordinator:        coordinator.lookup,
			Preparams:          fixture.preparams,
			Shares:             fixture.shares,
			SessionArtifacts:   fixture.artifacts,
		})
		if err != nil {
			t.Fatalf("participant.New() error = %v", err)
		}
		sessions[fixture.id.id] = session
	}
	return sessions
}

func driveSession(t *testing.T, sessionID string, sessions map[string]*ParticipantSession, coordinator coordinatorFixture) map[string]*Result {
	t.Helper()
	pending := make([]queuedMessage, 0, 64)
	results := make(map[string]*Result, len(sessions))

	for id, session := range sessions {
		effects, err := session.Start()
		if err != nil {
			t.Fatalf("Session.Start() error = %v", err)
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}
	for id, session := range sessions {
		ctrl := &protocol.ControlMessage{
			SessionID:     sessionID,
			Sequence:      1,
			CoordinatorID: coordinator.id,
			KeyExchange:   &protocol.KeyExchangeBegin{ExchangeID: "kx-1"},
		}
		payload := protocol.MustControlSigningBytes(ctrl)
		ctrl.Signature = ed25519.Sign(coordinator.priv, payload)

		effects, err := session.HandleControl(ctrl)
		if err != nil {
			t.Fatalf("HandleControl(KeyExchangeBegin) for %s error = %v", id, err)
		}
		if effects.Result != nil {
			results[id] = effects.Result
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}

	processQueue(t, sessions, &pending, results)

	for id, session := range sessions {
		ctrl := &protocol.ControlMessage{
			SessionID:     sessionID,
			Sequence:      2,
			CoordinatorID: coordinator.id,
			MPCBegin:      &protocol.MPCBegin{},
		}
		payload := protocol.MustControlSigningBytes(ctrl)
		ctrl.Signature = ed25519.Sign(coordinator.priv, payload)

		effects, err := session.HandleControl(ctrl)
		if err != nil {
			t.Fatalf("HandleControl(MPCBegin) for %s error = %v", id, err)
		}
		if effects.Result != nil {
			results[id] = effects.Result
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}

	processQueue(t, sessions, &pending, results)

	if len(results) != len(sessions) {
		t.Fatalf("driveSession() incomplete results: got=%d want=%d", len(results), len(sessions))
	}
	return results
}

func processQueue(
	t *testing.T,
	sessions map[string]*ParticipantSession,
	pending *[]queuedMessage,
	results map[string]*Result,
) {
	t.Helper()
	for step := 0; step < 200000 && len(results) < len(sessions); step++ {
		if len(*pending) == 0 {
			progressed := false
			for id, session := range sessions {
				effects, err := session.Tick(time.Now())
				if err != nil {
					t.Fatalf("Tick() for %s error = %v", id, err)
				}
				if effects.Result != nil {
					results[id] = effects.Result
				}
				if len(effects.PeerMessages) > 0 {
					progressed = true
				}
				*pending = appendPending(*pending, id, effects.PeerMessages)
			}
			if !progressed {
				return
			}
			continue
		}
		next := (*pending)[0]
		*pending = (*pending)[1:]

		targets := make([]string, 0, len(sessions))
		if next.msg.ToParticipantID != "" {
			targets = append(targets, next.msg.ToParticipantID)
		} else if next.msg.Broadcast {
			for id := range sessions {
				if id != next.sender {
					targets = append(targets, id)
				}
			}
		}

		for _, targetID := range targets {
			targetSession := sessions[targetID]
			if targetSession == nil {
				continue
			}
			if targetSession.Status().Phase == protocol.ParticipantPhaseCompleted {
				continue
			}
			effects, err := targetSession.HandlePeer(next.msg)
			if err != nil {
				t.Fatalf("HandlePeer() target=%s sender=%s error=%v", targetID, next.sender, err)
			}
			if effects.Result != nil {
				results[targetID] = effects.Result
			}
			*pending = appendPending(*pending, targetID, effects.PeerMessages)
		}
	}
}

func appendPending(queue []queuedMessage, sender string, messages []*protocol.PeerMessage) []queuedMessage {
	for _, message := range messages {
		queue = append(queue, queuedMessage{sender: sender, msg: message})
	}
	return queue
}

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

type testCoordinatorLookup struct{ keys map[string]ed25519.PublicKey }

func (l *testCoordinatorLookup) LookupCoordinator(coordinatorID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[coordinatorID]
	if !ok {
		return nil, fmt.Errorf("coordinator %s not found", coordinatorID)
	}
	return key, nil
}

type memoryPreparamsStore struct{ values map[string][]byte }

func (s *memoryPreparamsStore) key(protocolType protocol.ProtocolType, keyID string) string {
	return string(protocolType) + ":" + keyID
}

func (s *memoryPreparamsStore) LoadPreparams(protocolType protocol.ProtocolType, keyID string) ([]byte, error) {
	return append([]byte(nil), s.values[s.key(protocolType, keyID)]...), nil
}

func (s *memoryPreparamsStore) SavePreparams(protocolType protocol.ProtocolType, keyID string, preparams []byte) error {
	s.values[s.key(protocolType, keyID)] = append([]byte(nil), preparams...)
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

type memorySessionArtifactsStore struct{ values map[string][]byte }

func (s *memorySessionArtifactsStore) LoadSessionArtifacts(sessionID string) ([]byte, error) {
	return append([]byte(nil), s.values[sessionID]...), nil
}

func (s *memorySessionArtifactsStore) SaveSessionArtifacts(sessionID string, artifact []byte) error {
	s.values[sessionID] = append([]byte(nil), artifact...)
	return nil
}

func (s *memorySessionArtifactsStore) DeleteSessionArtifacts(sessionID string) error {
	delete(s.values, sessionID)
	return nil
}
