package participant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium-sdk/storage"
)

func TestSessionECDSAKeygenAndSign(t *testing.T) {
	participants, Orchestrator, err := newTestParticipants(3)
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
		if saveErr := participants[i].preparams.SavePreparamsSlot(protocol.ProtocolTypeECDSA, "bootstrap", blob); saveErr != nil {
			t.Fatalf("SavePreparamsSlot() error = %v", saveErr)
		}
		if saveActiveErr := participants[i].preparams.SaveActivePreparamsSlot(protocol.ProtocolTypeECDSA, "bootstrap"); saveActiveErr != nil {
			t.Fatalf("SaveActivePreparamsSlot() error = %v", saveActiveErr)
		}
	}

	sessions := createSessions(t, keygenStart, participants, Orchestrator)
	keygenResults := driveSession(t, keygenStart.SessionID, sessions, Orchestrator)
	for id, result := range keygenResults {
		if result == nil || result.KeyShare == nil || len(result.KeyShare.ShareBlob) == 0 {
			t.Fatalf("keygen result missing share blob for %s", id)
		}
		if got := len(result.KeyShare.PublicKey); got != 65 {
			t.Fatalf("ecdsa public key len for %s = %d, want 65", id, got)
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

	signSessions := createSessions(t, signStart, participants, Orchestrator)
	signResults := driveSession(t, signStart.SessionID, signSessions, Orchestrator)
	for id, result := range signResults {
		if result == nil || result.Signature == nil || len(result.Signature.Signature) == 0 {
			t.Fatalf("sign result missing signature for %s", id)
		}
	}
}

func TestSessionEdDSAKeygenAndSign(t *testing.T) {
	participants, Orchestrator, err := newTestParticipants(3)
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

	sessions := createSessions(t, keygenStart, participants, Orchestrator)
	keygenResults := driveSession(t, keygenStart.SessionID, sessions, Orchestrator)
	for id, result := range keygenResults {
		if result == nil || result.KeyShare == nil || len(result.KeyShare.ShareBlob) == 0 {
			t.Fatalf("keygen result missing share blob for %s", id)
		}
		if got := len(result.KeyShare.PublicKey); got != ed25519.PublicKeySize {
			t.Fatalf("eddsa public key len for %s = %d, want %d", id, got, ed25519.PublicKeySize)
		}
		if _, err := edwards.ParsePubKey(result.KeyShare.PublicKey); err != nil {
			t.Fatalf("eddsa public key for %s is not compressed Ed25519: %v", id, err)
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

	signSessions := createSessions(t, signStart, participants, Orchestrator)
	signResults := driveSession(t, signStart.SessionID, signSessions, Orchestrator)
	for id, result := range signResults {
		if result == nil || result.Signature == nil || len(result.Signature.Signature) == 0 {
			t.Fatalf("sign result missing signature for %s", id)
		}
	}
}

func TestSessionReshareAndSignWithNewCommittee(t *testing.T) {
	for _, protocolType := range []protocol.ProtocolType{protocol.ProtocolTypeECDSA, protocol.ProtocolTypeEdDSA} {
		protocolType := protocolType
		t.Run(string(protocolType), func(t *testing.T) {
			testSessionReshareAndSignWithNewCommittee(t, protocolType)
		})
	}
}

func testSessionReshareAndSignWithNewCommittee(t *testing.T, protocolType protocol.ProtocolType) {
	t.Helper()
	participants, Orchestrator, err := newTestParticipants(4)
	if err != nil {
		t.Fatalf("newTestParticipants() error = %v", err)
	}
	keyID := strings.ToLower(string(protocolType)) + "-reshare-key"
	oldCommittee := []*protocol.SessionParticipant{
		{ParticipantID: participants[0].id.ParticipantID(), PartyKey: []byte("old-1"), IdentityPublicKey: participants[0].id.pub},
		{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte("old-2"), IdentityPublicKey: participants[1].id.pub},
		{ParticipantID: participants[2].id.ParticipantID(), PartyKey: []byte("old-3"), IdentityPublicKey: participants[2].id.pub},
	}
	newCommittee := []*protocol.SessionParticipant{
		{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte("new-2"), IdentityPublicKey: participants[1].id.pub},
		{ParticipantID: participants[2].id.ParticipantID(), PartyKey: []byte("new-3"), IdentityPublicKey: participants[2].id.pub},
		{ParticipantID: participants[3].id.ParticipantID(), PartyKey: []byte("new-4"), IdentityPublicKey: participants[3].id.pub},
	}

	if protocolType == protocol.ProtocolTypeECDSA {
		fixtureKeys, _, fixtureErr := ecdsaKeygen.LoadKeygenTestFixtures(4)
		if fixtureErr != nil {
			t.Fatalf("LoadKeygenTestFixtures() error = %v", fixtureErr)
		}
		for i := range participants {
			blob, encodeErr := encodeECDSAPreparams(&fixtureKeys[i].LocalPreParams)
			if encodeErr != nil {
				t.Fatalf("encodeECDSAPreparams() error = %v", encodeErr)
			}
			if err := participants[i].preparams.SavePreparamsSlot(protocolType, "bootstrap", blob); err != nil {
				t.Fatalf("SavePreparamsSlot() error = %v", err)
			}
			if err := participants[i].preparams.SaveActivePreparamsSlot(protocolType, "bootstrap"); err != nil {
				t.Fatalf("SaveActivePreparamsSlot() error = %v", err)
			}
		}
	}

	keygenStart := &protocol.SessionStart{
		SessionID:    "session-" + strings.ToLower(string(protocolType)) + "-reshare-keygen",
		Protocol:     protocolType,
		Operation:    protocol.OperationTypeKeygen,
		Threshold:    1,
		Participants: oldCommittee,
		Keygen:       &protocol.KeygenPayload{KeyID: keyID},
	}
	keygenSessions := createSessions(t, keygenStart, participants[:3], Orchestrator)
	keygenResults := driveSession(t, keygenStart.SessionID, keygenSessions, Orchestrator)
	originalPublicKey := cloneBytes(keygenResults[participants[0].id.id].KeyShare.PublicKey)

	activeBefore := make(map[string][]byte, len(participants))
	for i := range participants {
		activeBefore[participants[i].id.id], err = participants[i].shares.LoadShare(protocolType, keyID)
		if err != nil {
			t.Fatalf("LoadShare(before) error = %v", err)
		}
	}

	reshareStart := &protocol.SessionStart{
		SessionID:    "session-" + strings.ToLower(string(protocolType)) + "-reshare",
		Protocol:     protocolType,
		Operation:    protocol.OperationTypeReshare,
		Threshold:    1,
		Participants: oldCommittee,
		Reshare: &protocol.ResharePayload{
			KeyID:           keyID,
			NewThreshold:    2,
			NewParticipants: newCommittee,
		},
	}
	reshareSessions := createSessions(t, reshareStart, participants, Orchestrator)
	driveReshareToPrepared(t, reshareStart.SessionID, reshareSessions, Orchestrator)

	for i := range participants {
		participantID := participants[i].id.id
		if phase := reshareSessions[participantID].Status().Phase; phase != protocol.ParticipantPhaseResharePrepared {
			t.Fatalf("phase for %s = %s, want %s", participantID, phase, protocol.ParticipantPhaseResharePrepared)
		}
		active, loadErr := participants[i].shares.LoadShare(protocolType, keyID)
		if loadErr != nil {
			t.Fatalf("LoadShare(prepared) error = %v", loadErr)
		}
		if !bytes.Equal(active, activeBefore[participantID]) {
			t.Fatalf("active share changed before commit for %s", participantID)
		}
	}

	// Recreate a prepared new-only participant from its durable checkpoint;
	// it must still be able to accept the commit without rerunning TSS.
	restarted, err := New(Config{
		Start:              reshareStart,
		LocalParticipantID: participants[3].id.id,
		Identity:           participants[3].id,
		Peers:              participants[3].lookup,
		Orchestrator:       Orchestrator.lookup,
		Preparams:          participants[3].preparams,
		Shares:             participants[3].shares,
		ShareRotations:     participants[3].rotations,
		SessionCheckpoint:  participants[3].checkpoints,
	})
	if err != nil {
		t.Fatalf("New(restarted prepared participant) error = %v", err)
	}
	if phase := restarted.Status().Phase; phase != protocol.ParticipantPhaseResharePrepared {
		t.Fatalf("restarted phase = %s, want %s", phase, protocol.ParticipantPhaseResharePrepared)
	}
	reshareSessions[participants[3].id.id] = restarted

	for id, session := range reshareSessions {
		commit := signedControl(reshareStart.SessionID, 3, Orchestrator, func(message *protocol.ControlMessage) {
			message.ReshareCommit = &protocol.ReshareCommit{}
		})
		effects, err := session.HandleControl(commit)
		if err != nil {
			t.Fatalf("HandleControl(ReshareCommit) for %s error = %v", id, err)
		}
		if effects.Result == nil || effects.Result.Reshare == nil {
			t.Fatalf("reshare commit result missing for %s", id)
		}
		if !bytes.Equal(effects.Result.Reshare.PublicKey, originalPublicKey) {
			t.Fatalf("public key changed for %s", id)
		}
	}

	retired, err := participants[0].shares.LoadShare(protocolType, keyID)
	if err != nil {
		t.Fatalf("LoadShare(retired) error = %v", err)
	}
	if len(retired) != 0 {
		t.Fatal("old-only participant share was not retired")
	}
	for _, index := range []int{1, 2, 3} {
		active, loadErr := participants[index].shares.LoadShare(protocolType, keyID)
		if loadErr != nil {
			t.Fatalf("LoadShare(committed) error = %v", loadErr)
		}
		if len(active) == 0 || bytes.Equal(active, activeBefore[participants[index].id.id]) {
			t.Fatalf("new share was not activated for %s", participants[index].id.id)
		}
	}

	duplicateCommit := signedControl(reshareStart.SessionID, 4, Orchestrator, func(message *protocol.ControlMessage) {
		message.ReshareCommit = &protocol.ReshareCommit{}
	})
	if _, err := reshareSessions[participants[1].id.id].HandleControl(duplicateCommit); err != nil {
		t.Fatalf("duplicate ReshareCommit error = %v", err)
	}

	signStart := &protocol.SessionStart{
		SessionID:    "session-" + strings.ToLower(string(protocolType)) + "-post-reshare-sign",
		Protocol:     protocolType,
		Operation:    protocol.OperationTypeSign,
		Threshold:    2,
		Participants: newCommittee,
		Sign:         &protocol.SignPayload{KeyID: keyID, SigningInput: []byte("post-reshare-message")},
	}
	signSessions := createSessions(t, signStart, participants[1:], Orchestrator)
	signResults := driveSession(t, signStart.SessionID, signSessions, Orchestrator)
	for id, result := range signResults {
		if result == nil || result.Signature == nil || len(result.Signature.Signature) == 0 {
			t.Fatalf("post-reshare signature missing for %s", id)
		}
	}
}

func driveReshareToPrepared(t *testing.T, sessionID string, sessions map[string]*ParticipantSession, Orchestrator OrchestratorFixture) {
	t.Helper()
	pending := make([]queuedMessage, 0, 128)
	results := make(map[string]*Result)
	for id, session := range sessions {
		effects, err := session.Start()
		if err != nil {
			t.Fatalf("Start() for %s error = %v", id, err)
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}
	for id, session := range sessions {
		control := signedControl(sessionID, 1, Orchestrator, func(message *protocol.ControlMessage) {
			message.KeyExchange = &protocol.KeyExchangeBegin{ExchangeID: "kx-reshare"}
		})
		effects, err := session.HandleControl(control)
		if err != nil {
			t.Fatalf("HandleControl(KeyExchange) for %s error = %v", id, err)
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}
	processQueue(t, sessions, &pending, results)
	for id, session := range sessions {
		control := signedControl(sessionID, 2, Orchestrator, func(message *protocol.ControlMessage) {
			message.MPCBegin = &protocol.MPCBegin{}
		})
		effects, err := session.HandleControl(control)
		if err != nil {
			t.Fatalf("HandleControl(MPCBegin) for %s error = %v", id, err)
		}
		pending = appendPending(pending, id, effects.PeerMessages)
	}
	processQueue(t, sessions, &pending, results)
}

func signedControl(sessionID string, sequence uint64, Orchestrator OrchestratorFixture, fill func(*protocol.ControlMessage)) *protocol.ControlMessage {
	message := &protocol.ControlMessage{SessionID: sessionID, Sequence: sequence, OrchestratorID: Orchestrator.id}
	fill(message)
	message.Signature = ed25519.Sign(Orchestrator.priv, protocol.MustControlSigningBytes(message))
	return message
}

func TestSessionRejectsMPCBeginBeforeKeyExchange(t *testing.T) {
	participants, Orchestrator, err := newTestParticipants(2)
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
	session := createSessions(t, start, participants[:1], Orchestrator)[participants[0].id.id]
	if _, err := session.Start(); err != nil {
		t.Fatalf("Session.Start() error = %v", err)
	}
	ctrl := &protocol.ControlMessage{
		SessionID:      start.SessionID,
		Sequence:       1,
		OrchestratorID: Orchestrator.id,
		MPCBegin:       &protocol.MPCBegin{},
	}
	ctrl.Signature = ed25519.Sign(Orchestrator.priv, protocol.MustControlSigningBytes(ctrl))
	if _, err := session.HandleControl(ctrl); err != ErrKeyExchangeRequired {
		t.Fatalf("HandleControl(MPCBegin) error = %v, want %v", err, ErrKeyExchangeRequired)
	}
}

func TestNewRejectsLocalIdentityPublicKeyMismatch(t *testing.T) {
	participants, Orchestrator, err := newTestParticipants(2)
	if err != nil {
		t.Fatalf("newTestParticipants() error = %v", err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	start := &protocol.SessionStart{
		SessionID: "session-key-mismatch",
		Protocol:  protocol.ProtocolTypeEdDSA,
		Operation: protocol.OperationTypeKeygen,
		Threshold: 1,
		Participants: []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.ParticipantID(), PartyKey: []byte{1}, IdentityPublicKey: wrongPub},
			{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte{2}, IdentityPublicKey: participants[1].id.pub},
		},
		Keygen: &protocol.KeygenPayload{KeyID: "eddsa-key"},
	}

	_, err = New(Config{
		Start:              start,
		LocalParticipantID: participants[0].id.id,
		Identity:           participants[0].id,
		Peers:              participants[0].lookup,
		Orchestrator:       Orchestrator.lookup,
		Preparams:          participants[0].preparams,
		Shares:             participants[0].shares,
		SessionCheckpoint:  participants[0].checkpoints,
	})
	if err == nil || !strings.Contains(err.Error(), "identity public key mismatch") {
		t.Fatalf("participant.New() error = %v, want identity public key mismatch", err)
	}
}

func TestReshareCommitRequiresPreparedAndAbortPreservesActiveShare(t *testing.T) {
	participants, Orchestrator, err := newTestParticipants(3)
	if err != nil {
		t.Fatalf("newTestParticipants() error = %v", err)
	}
	start := &protocol.SessionStart{
		SessionID: "session-reshare-control-phase",
		Protocol:  protocol.ProtocolTypeEdDSA,
		Operation: protocol.OperationTypeReshare,
		Threshold: 1,
		Participants: []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.id, PartyKey: []byte("old-1"), IdentityPublicKey: participants[0].id.pub},
			{ParticipantID: participants[1].id.id, PartyKey: []byte("old-2"), IdentityPublicKey: participants[1].id.pub},
		},
		Reshare: &protocol.ResharePayload{
			KeyID:        "wallet-1",
			NewThreshold: 1,
			NewParticipants: []*protocol.SessionParticipant{
				{ParticipantID: participants[1].id.id, PartyKey: []byte("new-2"), IdentityPublicKey: participants[1].id.pub},
				{ParticipantID: participants[2].id.id, PartyKey: []byte("new-3"), IdentityPublicKey: participants[2].id.pub},
			},
		},
	}
	if err := participants[0].shares.SaveShare(start.Protocol, start.Reshare.KeyID, []byte("active-old-share")); err != nil {
		t.Fatalf("SaveShare() error = %v", err)
	}
	session := createSessions(t, start, participants[:1], Orchestrator)[participants[0].id.id]
	commit := signedControl(start.SessionID, 1, Orchestrator, func(message *protocol.ControlMessage) {
		message.ReshareCommit = &protocol.ReshareCommit{}
	})
	if _, err := session.HandleControl(commit); !errors.Is(err, ErrReshareCommitPhase) {
		t.Fatalf("HandleControl(commit before prepared) error = %v, want %v", err, ErrReshareCommitPhase)
	}

	if err := participants[0].rotations.StageShareRotation(start.Protocol, start.Reshare.KeyID, start.SessionID, storage.ShareRotation{Retire: true}); err != nil {
		t.Fatalf("StageShareRotation() error = %v", err)
	}
	abort := signedControl(start.SessionID, 2, Orchestrator, func(message *protocol.ControlMessage) {
		message.SessionAbort = &protocol.SessionAbort{Reason: protocol.FailureReasonAborted, Detail: "test abort"}
	})
	if _, err := session.HandleControl(abort); err != nil {
		t.Fatalf("HandleControl(abort) error = %v", err)
	}
	active, err := participants[0].shares.LoadShare(start.Protocol, start.Reshare.KeyID)
	if err != nil {
		t.Fatalf("LoadShare() error = %v", err)
	}
	if string(active) != "active-old-share" {
		t.Fatalf("active share after abort = %q", active)
	}
}

type participantFixture struct {
	id          *testIdentity
	lookup      *testPeerLookup
	preparams   *memoryPreparamsStore
	shares      *memoryShareStore
	rotations   *memoryShareRotationStore
	checkpoints *memorySessionCheckpointStore
}

type OrchestratorFixture struct {
	id     string
	priv   ed25519.PrivateKey
	lookup *testOrchestratorLookup
}

type queuedMessage struct {
	sender string
	msg    *protocol.PeerMessage
}

func newTestParticipants(count int) ([]participantFixture, OrchestratorFixture, error) {
	peerLookup := &testPeerLookup{keys: make(map[string]ed25519.PublicKey, count)}
	fixtures := make([]participantFixture, 0, count)
	for i := 0; i < count; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, OrchestratorFixture{}, err
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
	OrchestratorPub, OrchestratorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, OrchestratorFixture{}, err
	}
	OrchestratorLookup := &testOrchestratorLookup{keys: map[string]ed25519.PublicKey{"orch-1": OrchestratorPub}}
	return fixtures, OrchestratorFixture{id: "orch-1", priv: OrchestratorPriv, lookup: OrchestratorLookup}, nil
}

func createSessions(t *testing.T, start *protocol.SessionStart, fixtures []participantFixture, Orchestrator OrchestratorFixture) map[string]*ParticipantSession {
	t.Helper()
	sessions := make(map[string]*ParticipantSession, len(fixtures))
	for _, fixture := range fixtures {
		session, err := New(Config{
			Start:              start,
			LocalParticipantID: fixture.id.id,
			Identity:           fixture.id,
			Peers:              fixture.lookup,
			Orchestrator:       Orchestrator.lookup,
			Preparams:          fixture.preparams,
			Shares:             fixture.shares,
			ShareRotations:     fixture.rotations,
			SessionCheckpoint:  fixture.checkpoints,
		})
		if err != nil {
			t.Fatalf("participant.New() error = %v", err)
		}
		sessions[fixture.id.id] = session
	}
	return sessions
}

func driveSession(t *testing.T, sessionID string, sessions map[string]*ParticipantSession, Orchestrator OrchestratorFixture) map[string]*Result {
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
			SessionID:      sessionID,
			Sequence:       1,
			OrchestratorID: Orchestrator.id,
			KeyExchange:    &protocol.KeyExchangeBegin{ExchangeID: "kx-1"},
		}
		payload := protocol.MustControlSigningBytes(ctrl)
		ctrl.Signature = ed25519.Sign(Orchestrator.priv, payload)

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
			SessionID:      sessionID,
			Sequence:       2,
			OrchestratorID: Orchestrator.id,
			MPCBegin:       &protocol.MPCBegin{},
		}
		payload := protocol.MustControlSigningBytes(ctrl)
		ctrl.Signature = ed25519.Sign(Orchestrator.priv, payload)

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

type testOrchestratorLookup struct{ keys map[string]ed25519.PublicKey }

func (l *testOrchestratorLookup) LookupOrchestrator(OrchestratorID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[OrchestratorID]
	if !ok {
		return nil, fmt.Errorf("orchestrator %s not found", OrchestratorID)
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
