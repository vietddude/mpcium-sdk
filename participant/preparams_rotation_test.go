package participant

import (
	"testing"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/fystack/mpcium-sdk/protocol"
)

func TestRotatePreparamsSlotPromotesNextAndCopiesPrev(t *testing.T) {
	fixtures, _, err := ecdsaKeygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatalf("LoadKeygenTestFixtures() error = %v", err)
	}
	activeBlob, err := encodeECDSAPreparams(&fixtures[0].LocalPreParams)
	if err != nil {
		t.Fatalf("encodeECDSAPreparams(active) error = %v", err)
	}
	nextBlob, err := encodeECDSAPreparams(&fixtures[1].LocalPreParams)
	if err != nil {
		t.Fatalf("encodeECDSAPreparams(next) error = %v", err)
	}

	store := &memoryPreparamsStore{
		values:      map[string][]byte{},
		activeSlots: map[string]string{},
	}
	if err := store.SavePreparamsSlot(protocol.ProtocolTypeECDSA, "slot-a", activeBlob); err != nil {
		t.Fatalf("SavePreparamsSlot(slot-a) error = %v", err)
	}
	if err := store.SavePreparamsSlot(protocol.ProtocolTypeECDSA, PreparamsSlotNext, nextBlob); err != nil {
		t.Fatalf("SavePreparamsSlot(next) error = %v", err)
	}
	if err := store.SaveActivePreparamsSlot(protocol.ProtocolTypeECDSA, "slot-a"); err != nil {
		t.Fatalf("SaveActivePreparamsSlot(slot-a) error = %v", err)
	}

	if err := RotatePreparamsSlot(store, protocol.ProtocolTypeECDSA, PreparamsSlotNext); err != nil {
		t.Fatalf("RotatePreparamsSlot() error = %v", err)
	}
	activeSlot, err := store.LoadActivePreparamsSlot(protocol.ProtocolTypeECDSA)
	if err != nil {
		t.Fatalf("LoadActivePreparamsSlot() error = %v", err)
	}
	if activeSlot != PreparamsSlotNext {
		t.Fatalf("activeSlot = %q, want %q", activeSlot, PreparamsSlotNext)
	}
	prevBlob, err := store.LoadPreparamsSlot(protocol.ProtocolTypeECDSA, PreparamsSlotPrev)
	if err != nil {
		t.Fatalf("LoadPreparamsSlot(prev) error = %v", err)
	}
	if len(prevBlob) == 0 {
		t.Fatal("prev slot blob is empty")
	}
}

func TestRotatePreparamsSlotRejectsInvalidNextBlob(t *testing.T) {
	store := &memoryPreparamsStore{
		values:      map[string][]byte{},
		activeSlots: map[string]string{},
	}
	if err := store.SavePreparamsSlot(protocol.ProtocolTypeECDSA, PreparamsSlotNext, []byte("bad")); err != nil {
		t.Fatalf("SavePreparamsSlot(next) error = %v", err)
	}

	if err := RotatePreparamsSlot(store, protocol.ProtocolTypeECDSA, PreparamsSlotNext); err == nil {
		t.Fatal("RotatePreparamsSlot() error = nil, want invalid blob error")
	}
}
