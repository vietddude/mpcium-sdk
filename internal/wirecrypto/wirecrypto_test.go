package wirecrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/vietddude/mpcium-sdk/protocol"
)

func TestVerifyRejectsBadSignature(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if err := Verify(pub, []byte("payload"), []byte("bad-signature")); err != ErrInvalidSignature {
		t.Fatalf("Verify() error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestDirectEncryptionRoundTrip(t *testing.T) {
	t.Parallel()

	sender, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() sender error = %v", err)
	}
	recipient, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() recipient error = %v", err)
	}

	msg := validDirectMessage()
	nonce, ciphertext, err := EncryptDirect(sender, recipient.PublicKeyBytes(), msg, []byte("payload"))
	if err != nil {
		t.Fatalf("EncryptDirect() error = %v", err)
	}

	plaintext, err := DecryptDirect(recipient, sender.PublicKeyBytes(), msg, nonce, ciphertext)
	if err != nil {
		t.Fatalf("DecryptDirect() error = %v", err)
	}
	if string(plaintext) != "payload" {
		t.Fatalf("DecryptDirect() plaintext = %q", plaintext)
	}
}

func TestDirectEncryptionRejectsWrongSenderKey(t *testing.T) {
	t.Parallel()

	sender, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() sender error = %v", err)
	}
	recipient, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() recipient error = %v", err)
	}
	wrongSender, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() wrong sender error = %v", err)
	}

	msg := validDirectMessage()
	nonce, ciphertext, err := EncryptDirect(sender, recipient.PublicKeyBytes(), msg, []byte("payload"))
	if err != nil {
		t.Fatalf("EncryptDirect() error = %v", err)
	}

	if _, err := DecryptDirect(recipient, wrongSender.PublicKeyBytes(), msg, nonce, ciphertext); err == nil {
		t.Fatalf("DecryptDirect() error = nil, want failure")
	}
}

func TestDirectEncryptionRejectsTamperAndAADMismatch(t *testing.T) {
	t.Parallel()

	sender, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() sender error = %v", err)
	}
	recipient, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() recipient error = %v", err)
	}

	msg := validDirectMessage()
	nonce, ciphertext, err := EncryptDirect(sender, recipient.PublicKeyBytes(), msg, []byte("payload"))
	if err != nil {
		t.Fatalf("EncryptDirect() error = %v", err)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xff
	if _, err := DecryptDirect(recipient, sender.PublicKeyBytes(), msg, nonce, tampered); err == nil {
		t.Fatalf("DecryptDirect() tampered error = nil, want failure")
	}

	mismatched := validDirectMessage()
	mismatched.Sequence = 99
	if _, err := DecryptDirect(recipient, sender.PublicKeyBytes(), mismatched, nonce, ciphertext); err == nil {
		t.Fatalf("DecryptDirect() aad mismatch error = nil, want failure")
	}
}

func validDirectMessage() *protocol.PeerMessage {
	return &protocol.PeerMessage{
		SessionId:         "session-1",
		Sequence:          1,
		FromParticipantId: "p1",
		ToParticipantId:   "p2",
		Phase:             protocol.ParticipantPhase_PARTICIPANT_PHASE_MPC_RUNNING,
		Body: &protocol.PeerMessage_MpcPacket{
			MpcPacket: &protocol.MpcPacket{},
		},
	}
}
