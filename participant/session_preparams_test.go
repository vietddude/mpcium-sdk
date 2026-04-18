package participant

import (
	"errors"
	"testing"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/fystack/mpcium-sdk/protocol"
)

func TestResolveECDSAPreparamsRequiresActiveSlot(t *testing.T) {
	session := newECDSAKeygenSessionForPreparams(t)

	_, err := session.resolveECDSAPreparams()
	if !errors.Is(err, ErrPreparamsSlotMissing) {
		t.Fatalf("resolveECDSAPreparams() error = %v, want %v", err, ErrPreparamsSlotMissing)
	}
}

func TestResolveECDSAPreparamsRejectsInvalidBlob(t *testing.T) {
	session := newECDSAKeygenSessionForPreparams(t)
	if err := session.cfg.Preparams.SavePreparamsSlot(protocol.ProtocolTypeECDSA, "slot-a", []byte("invalid")); err != nil {
		t.Fatalf("SavePreparamsSlot() error = %v", err)
	}
	if err := session.cfg.Preparams.SaveActivePreparamsSlot(protocol.ProtocolTypeECDSA, "slot-a"); err != nil {
		t.Fatalf("SaveActivePreparamsSlot() error = %v", err)
	}

	if _, err := session.resolveECDSAPreparams(); err == nil {
		t.Fatal("resolveECDSAPreparams() error = nil, want decode error")
	}
}

func TestResolveECDSAPreparamsPinsSessionSlot(t *testing.T) {
	session := newECDSAKeygenSessionForPreparams(t)
	fixtures, _, err := ecdsaKeygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatalf("LoadKeygenTestFixtures() error = %v", err)
	}
	blobA, err := encodeECDSAPreparams(&fixtures[0].LocalPreParams)
	if err != nil {
		t.Fatalf("encodeECDSAPreparams(slot-a) error = %v", err)
	}
	blobB, err := encodeECDSAPreparams(&fixtures[1].LocalPreParams)
	if err != nil {
		t.Fatalf("encodeECDSAPreparams(slot-b) error = %v", err)
	}

	store := session.cfg.Preparams.(*memoryPreparamsStore)
	if err := store.SavePreparamsSlot(protocol.ProtocolTypeECDSA, "slot-a", blobA); err != nil {
		t.Fatalf("SavePreparamsSlot(slot-a) error = %v", err)
	}
	if err := store.SaveActivePreparamsSlot(protocol.ProtocolTypeECDSA, "slot-a"); err != nil {
		t.Fatalf("SaveActivePreparamsSlot(slot-a) error = %v", err)
	}
	if _, err := session.resolveECDSAPreparams(); err != nil {
		t.Fatalf("resolveECDSAPreparams(slot-a) error = %v", err)
	}
	if session.preparamsSlot != "slot-a" {
		t.Fatalf("session.preparamsSlot = %q, want slot-a", session.preparamsSlot)
	}

	// Rotate global active slot; in-flight session keeps pinned slot.
	if err := store.SavePreparamsSlot(protocol.ProtocolTypeECDSA, "slot-b", blobB); err != nil {
		t.Fatalf("SavePreparamsSlot(slot-b) error = %v", err)
	}
	if err := store.SaveActivePreparamsSlot(protocol.ProtocolTypeECDSA, "slot-b"); err != nil {
		t.Fatalf("SaveActivePreparamsSlot(slot-b) error = %v", err)
	}
	delete(store.values, store.key(protocol.ProtocolTypeECDSA, "slot-a"))

	_, err = session.resolveECDSAPreparams()
	if !errors.Is(err, ErrPreparamsBlobMissing) {
		t.Fatalf("resolveECDSAPreparams() error = %v, want %v", err, ErrPreparamsBlobMissing)
	}
}

func newECDSAKeygenSessionForPreparams(t *testing.T) *ParticipantSession {
	t.Helper()
	participants, coordinator, err := newTestParticipants(2)
	if err != nil {
		t.Fatalf("newTestParticipants() error = %v", err)
	}
	start := &protocol.SessionStart{
		SessionID: "session-preparams-test",
		Protocol:  protocol.ProtocolTypeECDSA,
		Operation: protocol.OperationTypeKeygen,
		Threshold: 1,
		Participants: []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.ParticipantID(), PartyKey: []byte{1}, IdentityPublicKey: participants[0].id.pub},
			{ParticipantID: participants[1].id.ParticipantID(), PartyKey: []byte{2}, IdentityPublicKey: participants[1].id.pub},
		},
		Keygen: &protocol.KeygenPayload{KeyID: "preparams-test-key"},
	}
	sessions := createSessions(t, start, participants[:1], coordinator)
	return sessions[participants[0].id.id]
}
