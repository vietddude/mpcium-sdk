package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/vietddude/mpcium-sdk/participant"
	"github.com/vietddude/mpcium-sdk/protocol"
)

type queuedMessage struct {
	sender string
	msg    *protocol.PeerMessage
}

func main() {
	participants, coordinator, err := newTestParticipants(3)
	if err != nil {
		log.Fatalf("newTestParticipants: %v", err)
	}

	start := &protocol.SessionStart{
		SessionID: "demo-keygen-eddsa-1",
		Protocol:  protocol.ProtocolTypeEdDSA,
		Operation: protocol.OperationTypeKeygen,
		Threshold: 1,
		Participants: []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.ParticipantID(), PartyKey: []byte{1}, IdentityPublicKey: participants[0].id.pub},
			{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte{2}, IdentityPublicKey: participants[1].id.pub},
			{ParticipantID: participants[2].id.ParticipantID(), PartyKey: []byte{3}, IdentityPublicKey: participants[2].id.pub},
		},
		Keygen: &protocol.KeygenPayload{KeyID: "demo-wallet-key-1"},
	}

	sessions := createSessions(start, participants, coordinator)
	results, err := driveKeygenFlow(start.SessionID, sessions, coordinator)
	if err != nil {
		log.Fatalf("driveKeygenFlow: %v", err)
	}

	fmt.Println("KEYGEN DONE")
	for participantID, result := range results {
		fmt.Printf("participant=%s key_id=%s share_blob_size=%d public_key_size=%d\n",
			participantID,
			result.KeyShare.KeyID,
			len(result.KeyShare.ShareBlob),
			len(result.KeyShare.PublicKey),
		)
	}
}

func driveKeygenFlow(
	sessionID string,
	sessions map[string]*participant.ParticipantSession,
	coordinator coordinatorFixture,
) (map[string]*protocol.Result, error) {
	pending := make([]queuedMessage, 0, 64)
	results := make(map[string]*protocol.Result, len(sessions))

	for id, sess := range sessions {
		effects, err := sess.Start()
		if err != nil {
			return nil, fmt.Errorf("%s Start: %w", id, err)
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}

	for id, sess := range sessions {
		ctrl := &protocol.ControlMessage{
			SessionID:     sessionID,
			Sequence:      1,
			CoordinatorID: coordinator.id,
			KeyExchange:   &protocol.KeyExchangeBegin{ExchangeID: "kx-demo-1"},
		}
		if err := signControl(coordinator.priv, ctrl); err != nil {
			return nil, err
		}
		effects, err := sess.HandleControl(ctrl)
		if err != nil {
			return nil, fmt.Errorf("%s HandleControl(KeyExchangeBegin): %w", id, err)
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}

	if err := processQueue(sessions, &pending, results); err != nil {
		return nil, err
	}

	for id, sess := range sessions {
		ctrl := &protocol.ControlMessage{
			SessionID:     sessionID,
			Sequence:      2,
			CoordinatorID: coordinator.id,
			MPCBegin:      &protocol.MPCBegin{},
		}
		if err := signControl(coordinator.priv, ctrl); err != nil {
			return nil, err
		}
		effects, err := sess.HandleControl(ctrl)
		if err != nil {
			return nil, fmt.Errorf("%s HandleControl(MPCBegin): %w", id, err)
		}
		if effects.Result != nil {
			results[id] = effects.Result
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}

	if err := processQueue(sessions, &pending, results); err != nil {
		return nil, err
	}
	if len(results) != len(sessions) {
		return nil, fmt.Errorf("incomplete results: got=%d want=%d", len(results), len(sessions))
	}
	for id, result := range results {
		if result == nil || result.KeyShare == nil || len(result.KeyShare.ShareBlob) == 0 {
			return nil, fmt.Errorf("missing key share result for %s", id)
		}
	}
	return results, nil
}

func processQueue(
	sessions map[string]*participant.ParticipantSession,
	pending *[]queuedMessage,
	results map[string]*protocol.Result,
) error {
	for step := 0; step < 200000 && len(results) < len(sessions); step++ {
		if len(*pending) == 0 {
			progressed := false
			for id, session := range sessions {
				effects, err := session.Tick(time.Now())
				if err != nil {
					return fmt.Errorf("Tick %s: %w", id, err)
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
				return nil
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
				return fmt.Errorf("HandlePeer target=%s sender=%s: %w", targetID, next.sender, err)
			}
			if effects.Result != nil {
				results[targetID] = effects.Result
			}
			*pending = appendPending(*pending, targetID, effects.PeerMessages)
		}
	}
	return nil
}

func appendPending(queue []queuedMessage, sender string, messages []*protocol.PeerMessage) []queuedMessage {
	for _, message := range messages {
		queue = append(queue, queuedMessage{sender: sender, msg: message})
	}
	return queue
}

func createSessions(
	start *protocol.SessionStart,
	fixtures []participantFixture,
	coordinator coordinatorFixture,
) map[string]*participant.ParticipantSession {
	sessions := make(map[string]*participant.ParticipantSession, len(fixtures))
	for _, fixture := range fixtures {
		sess, err := participant.New(participant.Config{
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
			log.Fatalf("participant.New(%s): %v", fixture.id.id, err)
		}
		sessions[fixture.id.id] = sess
	}
	return sessions
}

func signControl(priv ed25519.PrivateKey, msg *protocol.ControlMessage) error {
	payload, err := protocol.ControlSigningBytes(msg)
	if err != nil {
		return err
	}
	msg.Signature = ed25519.Sign(priv, payload)
	return nil
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
