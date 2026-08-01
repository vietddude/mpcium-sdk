// In-memory harness: identities, lookups, stores, and the message pump that
// relays PeerMessages between local sessions. This mirrors what the
// orchestrator + transport layer do in a real deployment.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/fystack/mpcium-sdk/participant"
	"github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium-sdk/storage"
)

type queuedMessage struct {
	sender string
	msg    *protocol.PeerMessage
}

// ---- session construction ---------------------------------------------

func createSessions(
	start *protocol.SessionStart,
	fixtures []participantFixture,
	orch orchestratorFixture,
) map[string]*participant.ParticipantSession {
	sessions := make(map[string]*participant.ParticipantSession, len(fixtures))
	for _, fixture := range fixtures {
		sess, err := participant.New(participant.Config{
			Start:              start,
			LocalParticipantID: fixture.id.id,
			Identity:           fixture.id,
			Peers:              fixture.lookup,
			Orchestrator:       orch.lookup,
			Preparams:          fixture.preparams,
			Shares:             fixture.shares,
			ShareRotations:     fixture.rotations,
			SessionCheckpoint:  fixture.checkpoints,
		})
		if err != nil {
			panic(fmt.Sprintf("participant.New(%s): %v", fixture.id.id, err))
		}
		sessions[fixture.id.id] = sess
	}
	return sessions
}

// ---- keygen driver ----------------------------------------------------

func driveKeygen(
	sessions map[string]*participant.ParticipantSession,
	orch orchestratorFixture,
) (map[string]*participant.Result, error) {
	pending := make([]queuedMessage, 0, 64)
	results := make(map[string]*participant.Result, len(sessions))

	for id, sess := range sessions {
		effects, err := sess.Start()
		if err != nil {
			return nil, fmt.Errorf("%s Start: %w", id, err)
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}
	if err := broadcastControl(sessions, &pending, results, orch, 1, func(m *protocol.ControlMessage) {
		m.KeyExchange = &protocol.KeyExchangeBegin{ExchangeID: "kx-keygen"}
	}); err != nil {
		return nil, err
	}
	if err := processQueue(sessions, &pending, results); err != nil {
		return nil, err
	}
	if err := broadcastControl(sessions, &pending, results, orch, 2, func(m *protocol.ControlMessage) {
		m.MPCBegin = &protocol.MPCBegin{}
	}); err != nil {
		return nil, err
	}
	if err := processQueue(sessions, &pending, results); err != nil {
		return nil, err
	}
	if len(results) != len(sessions) {
		return nil, fmt.Errorf("incomplete keygen results: got=%d want=%d", len(results), len(sessions))
	}
	return results, nil
}

// ---- reshare driver ---------------------------------------------------

func driveReshare(
	sessions map[string]*participant.ParticipantSession,
	orch orchestratorFixture,
) (map[string]*participant.Result, error) {
	pending := make([]queuedMessage, 0, 128)
	results := make(map[string]*participant.Result, len(sessions))

	for id, sess := range sessions {
		effects, err := sess.Start()
		if err != nil {
			return nil, fmt.Errorf("%s Start: %w", id, err)
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}
	// KeyExchange, then MPCBegin: this runs the TSS resharing rounds and
	// leaves every participant in the RESHARE_PREPARED phase (shares staged
	// but not yet activated).
	if err := broadcastControl(sessions, &pending, results, orch, 1, func(m *protocol.ControlMessage) {
		m.KeyExchange = &protocol.KeyExchangeBegin{ExchangeID: "kx-reshare"}
	}); err != nil {
		return nil, err
	}
	if err := processQueue(sessions, &pending, results); err != nil {
		return nil, err
	}
	if err := broadcastControl(sessions, &pending, results, orch, 2, func(m *protocol.ControlMessage) {
		m.MPCBegin = &protocol.MPCBegin{}
	}); err != nil {
		return nil, err
	}
	if err := processQueue(sessions, &pending, results); err != nil {
		return nil, err
	}

	// ReshareCommit: promote the staged share rotation. Only now are the old
	// shares replaced (or retired for old-only members).
	if err := broadcastControl(sessions, &pending, results, orch, 3, func(m *protocol.ControlMessage) {
		m.ReshareCommit = &protocol.ReshareCommit{}
	}); err != nil {
		return nil, err
	}
	if err := processQueue(sessions, &pending, results); err != nil {
		return nil, err
	}
	for id, r := range results {
		if r == nil || r.Reshare == nil {
			return nil, fmt.Errorf("reshare result missing for %s", id)
		}
	}
	return results, nil
}

// broadcastControl signs and delivers the same control message to every
// session, collecting any Result/PeerMessages produced.
func broadcastControl(
	sessions map[string]*participant.ParticipantSession,
	pending *[]queuedMessage,
	results map[string]*participant.Result,
	orch orchestratorFixture,
	sequence uint64,
	fill func(*protocol.ControlMessage),
) error {
	for id, sess := range sessions {
		ctrl := &protocol.ControlMessage{SessionID: sessionIDOf(sess), Sequence: sequence, OrchestratorID: orch.id}
		fill(ctrl)
		ctrl.Signature = ed25519.Sign(orch.priv, protocol.MustControlSigningBytes(ctrl))
		effects, err := sess.HandleControl(ctrl)
		if err != nil {
			return fmt.Errorf("%s HandleControl(seq=%d): %w", id, sequence, err)
		}
		if effects.Result != nil {
			results[id] = effects.Result
		}
		*pending = appendPending(*pending, id, effects.PeerMessages)
	}
	return nil
}

func sessionIDOf(sess *participant.ParticipantSession) string {
	return sess.Status().SessionID
}

// ---- message pump -----------------------------------------------------

func processQueue(
	sessions map[string]*participant.ParticipantSession,
	pending *[]queuedMessage,
	results map[string]*participant.Result,
) error {
	for step := 0; step < 200000; step++ {
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

// ---- fixtures ---------------------------------------------------------

type participantFixture struct {
	id          *testIdentity
	lookup      *testPeerLookup
	preparams   *memoryPreparamsStore
	shares      *memoryShareStore
	rotations   *memoryShareRotationStore
	checkpoints *memorySessionCheckpointStore
}

type orchestratorFixture struct {
	id     string
	priv   ed25519.PrivateKey
	lookup *testOrchestratorLookup
}

func newTestParticipants(count int) ([]participantFixture, orchestratorFixture, error) {
	peerLookup := &testPeerLookup{keys: make(map[string]ed25519.PublicKey, count)}
	fixtures := make([]participantFixture, 0, count)
	for i := 0; i < count; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, orchestratorFixture{}, err
		}
		identity := &testIdentity{id: fmt.Sprintf("peer-%d", i+1), pub: pub, priv: priv}
		peerLookup.keys[identity.id] = pub
		shares := &memoryShareStore{values: map[string][]byte{}}
		fixtures = append(fixtures, participantFixture{
			id:          identity,
			lookup:      peerLookup,
			preparams:   &memoryPreparamsStore{values: map[string][]byte{}, activeSlots: map[string]string{}},
			shares:      shares,
			rotations:   &memoryShareRotationStore{shares: shares, pending: map[string]storage.ShareRotation{}, committed: map[string]bool{}},
			checkpoints: &memorySessionCheckpointStore{values: map[string][]byte{}},
		})
	}
	orchPub, orchPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, orchestratorFixture{}, err
	}
	orchLookup := &testOrchestratorLookup{keys: map[string]ed25519.PublicKey{"orch-1": orchPub}}
	return fixtures, orchestratorFixture{id: "orch-1", priv: orchPriv, lookup: orchLookup}, nil
}
