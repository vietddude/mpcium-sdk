// Command reshare_flow drives a full EdDSA reshare ceremony entirely
// in-memory to demonstrate what reshare does — and, crucially, what it does
// NOT change:
//
//   - The wallet public key stays identical (same address).
//   - The KeyID stays identical.
//   - The cosigner / participant IDs are exactly the IDs you put in
//     Reshare.NewParticipants. If you keep the same IDs, the committee is
//     unchanged; only the secret key SHARES are rotated ("refreshed").
//
// The flow is: keygen with an old committee -> reshare (keeping the SAME 3
// cosigners) -> print before/after to prove the pubkey and IDs are stable
// while the share bytes changed.
//
// Run: go run ./examples/reshare_flow
package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/fystack/mpcium-sdk/protocol"
)

const (
	protocolType = protocol.ProtocolTypeECDSA
	keyID        = "demo-wallet-key-1"
)

func main() {
	scenario := flag.String("scenario", "refresh",
		"refresh = same 3 devices rotate shares; migrate = retire peer-1, onboard a brand-new device peer-4")
	flag.Parse()

	// Four devices exist. Each participantFixture is an INDEPENDENT device:
	// its own identity keypair, its own share/preparams/checkpoint stores.
	// peer-4 stands in for the "new machine". The keygen wallet lives on
	// peer-1..3; peer-4 only shows up if we migrate.
	participants, orch, err := newTestParticipants(4)
	if err != nil {
		log.Fatalf("newTestParticipants: %v", err)
	}
	if protocolType == protocol.ProtocolTypeECDSA {
		// Every device that will run a NEW-committee role needs its own
		// Paillier pre-params generated on that device beforehand — including
		// the brand-new peer-4. Here we seed all four.
		if err := seedECDSAPreparams(participants); err != nil {
			log.Fatalf("seedECDSAPreparams: %v", err)
		}
	}

	// ---- 1. Keygen on the original 3 devices ---------------------------
	oldCommittee := []*protocol.SessionParticipant{
		{ParticipantID: participants[0].id.id, PartyKey: []byte{1}, IdentityPublicKey: participants[0].id.pub},
		{ParticipantID: participants[1].id.id, PartyKey: []byte{2}, IdentityPublicKey: participants[1].id.pub},
		{ParticipantID: participants[2].id.id, PartyKey: []byte{3}, IdentityPublicKey: participants[2].id.pub},
	}
	keygenStart := &protocol.SessionStart{
		SessionID:    "demo-keygen",
		Protocol:     protocolType,
		Operation:    protocol.OperationTypeKeygen,
		Threshold:    1,
		Participants: oldCommittee,
		Keygen:       &protocol.KeygenPayload{KeyID: keyID},
	}
	keygenResults, err := driveKeygen(createSessions(keygenStart, participants[:3], orch), orch)
	if err != nil {
		log.Fatalf("driveKeygen: %v", err)
	}
	originalPubKey := keygenResults[participants[0].id.id].KeyShare.PublicKey

	// ---- 2. Build the reshare according to the chosen scenario ---------
	// `involved` is the union of old + new committee = every device that must
	// run a session (old-only devices retire, new-only devices onboard).
	var newCommittee []*protocol.SessionParticipant
	var involved []participantFixture
	switch *scenario {
	case "refresh":
		// Same 3 IDs, fresh PartyKeys. Nobody leaves, nobody joins.
		newCommittee = []*protocol.SessionParticipant{
			{ParticipantID: participants[0].id.id, PartyKey: []byte{11}, IdentityPublicKey: participants[0].id.pub},
			{ParticipantID: participants[1].id.id, PartyKey: []byte{12}, IdentityPublicKey: participants[1].id.pub},
			{ParticipantID: participants[2].id.id, PartyKey: []byte{13}, IdentityPublicKey: participants[2].id.pub},
		}
		involved = participants[:3]
	case "migrate":
		// Move the wallet OFF peer-1 ONTO a brand-new device peer-4.
		// peer-1 is old-only  -> its share is RETIRED (deleted).
		// peer-4 is new-only  -> it receives a freshly generated share.
		// peer-2, peer-3 overlap -> shares refreshed.
		newCommittee = []*protocol.SessionParticipant{
			{ParticipantID: participants[1].id.id, PartyKey: []byte{12}, IdentityPublicKey: participants[1].id.pub},
			{ParticipantID: participants[2].id.id, PartyKey: []byte{13}, IdentityPublicKey: participants[2].id.pub},
			{ParticipantID: participants[3].id.id, PartyKey: []byte{14}, IdentityPublicKey: participants[3].id.pub},
		}
		involved = participants[:4]
	default:
		log.Fatalf("unknown -scenario %q (use refresh|migrate)", *scenario)
	}

	fmt.Printf("=== SCENARIO: %s ===\n", *scenario)
	fmt.Printf("old committee: %s\n", committeeIDs(oldCommittee))
	fmt.Printf("new committee: %s\n\n", committeeIDs(newCommittee))

	fmt.Println("=== AFTER KEYGEN ===")
	fmt.Printf("public key : %s\n", hex.EncodeToString(originalPubKey))
	sharesBefore := snapshotShares(involved)
	for _, p := range involved {
		fmt.Printf("device %-8s share=%s\n", p.id.id, shortHex(sharesBefore[p.id.id]))
	}

	reshareStart := &protocol.SessionStart{
		SessionID:    "demo-reshare",
		Protocol:     protocolType,
		Operation:    protocol.OperationTypeReshare,
		Threshold:    1, // old threshold
		Participants: oldCommittee,
		Reshare: &protocol.ResharePayload{
			KeyID:           keyID,
			NewThreshold:    1,
			NewParticipants: newCommittee,
		},
	}
	reshareResults, err := driveReshare(createSessions(reshareStart, involved, orch), orch)
	if err != nil {
		log.Fatalf("driveReshare: %v", err)
	}

	fmt.Println("\n=== AFTER RESHARE ===")
	// The new-committee members carry the pubkey in their result. Read it
	// from any surviving new member.
	newPubKey := reshareResults[participants[1].id.id].Reshare.PublicKey
	fmt.Printf("public key : %s\n", hex.EncodeToString(newPubKey))
	sharesAfter := snapshotShares(involved)
	for _, p := range involved {
		state := "active"
		if len(sharesAfter[p.id.id]) == 0 {
			state = "RETIRED (share deleted)"
		}
		fmt.Printf("device %-8s share=%-27s %s\n", p.id.id, shortHex(sharesAfter[p.id.id]), state)
	}

	// ---- 3. Assertions -------------------------------------------------
	fmt.Println("\n=== VERDICT ===")
	fmt.Printf("public key unchanged : %v\n", bytes.Equal(originalPubKey, newPubKey))
	fmt.Printf("keyID unchanged      : %v (%s)\n", reshareResults[participants[1].id.id].Reshare.KeyID == keyID, keyID)

	// ---- 4. Dump result to a file for comparison -----------------------
	if err := dumpResult("reshare_result.json", involved, sharesBefore, sharesAfter, originalPubKey, newPubKey); err != nil {
		log.Fatalf("dumpResult: %v", err)
	}
	fmt.Println("\nwrote reshare_result.json")
}

func committeeIDs(members []*protocol.SessionParticipant) string {
	ids := make([]string, len(members))
	for i, m := range members {
		ids[i] = m.ParticipantID
	}
	return fmt.Sprintf("%v", ids)
}

// dumpResult writes before/after shares (full hex) per cosigner plus the
// pubkey/keyID to a JSON file so you can diff the new shares.
func dumpResult(
	path string,
	participants []participantFixture,
	before, after map[string][]byte,
	oldPub, newPub []byte,
) error {
	type shareEntry struct {
		CosignerID  string `json:"cosigner_id"`
		ShareBefore string `json:"share_before_hex"`
		ShareAfter  string `json:"share_after_hex"`
		Changed     bool   `json:"changed"`
		ShareBytes  int    `json:"share_after_bytes"`
	}
	out := struct {
		Protocol     string       `json:"protocol"`
		KeyID        string       `json:"key_id"`
		PubKeyBefore string       `json:"pubkey_before_hex"`
		PubKeyAfter  string       `json:"pubkey_after_hex"`
		PubKeySame   bool         `json:"pubkey_unchanged"`
		Cosigners    []shareEntry `json:"cosigners"`
	}{
		Protocol:     string(protocolType),
		KeyID:        keyID,
		PubKeyBefore: hex.EncodeToString(oldPub),
		PubKeyAfter:  hex.EncodeToString(newPub),
		PubKeySame:   bytes.Equal(oldPub, newPub),
	}
	for _, p := range participants {
		b, a := before[p.id.id], after[p.id.id]
		out.Cosigners = append(out.Cosigners, shareEntry{
			CosignerID:  p.id.id,
			ShareBefore: hex.EncodeToString(b),
			ShareAfter:  hex.EncodeToString(a),
			Changed:     !bytes.Equal(b, a),
			ShareBytes:  len(a),
		})
	}
	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o644)
}

// seedECDSAPreparams loads bundled tss-lib fixtures and stores the Paillier
// pre-parameters in each participant's "bootstrap" slot (gob-encoded, matching
// the SDK's own encoding), then marks that slot active. In production you'd
// generate these once with ecdsaKeygen.GeneratePreParams and persist them.
func seedECDSAPreparams(participants []participantFixture) error {
	fixtures, _, err := ecdsaKeygen.LoadKeygenTestFixtures(len(participants))
	if err != nil {
		return fmt.Errorf("LoadKeygenTestFixtures: %w", err)
	}
	for i := range participants {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(&fixtures[i].LocalPreParams); err != nil {
			return err
		}
		if err := participants[i].preparams.SavePreparamsSlot(protocolType, "bootstrap", buf.Bytes()); err != nil {
			return err
		}
		if err := participants[i].preparams.SaveActivePreparamsSlot(protocolType, "bootstrap"); err != nil {
			return err
		}
	}
	return nil
}

func snapshotShares(participants []participantFixture) map[string][]byte {
	out := make(map[string][]byte, len(participants))
	for _, p := range participants {
		blob, _ := p.shares.LoadShare(protocolType, keyID)
		out[p.id.id] = blob
	}
	return out
}

func shortHex(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) > 24 {
		return h[:24] + "…"
	}
	return h
}
