package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestValidateSessionStart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(start *SessionStart)
		wantErr error
	}{
		{name: "valid keygen", mutate: func(*SessionStart) {}, wantErr: nil},
		{
			name: "duplicate participant id",
			mutate: func(start *SessionStart) {
				start.Participants[1].ParticipantID = start.Participants[0].ParticipantID
			},
			wantErr: ErrDuplicateParticipantID,
		},
		{
			name: "duplicate party key",
			mutate: func(start *SessionStart) {
				start.Participants[1].PartyKey = append([]byte(nil), start.Participants[0].PartyKey...)
			},
			wantErr: ErrDuplicatePartyKey,
		},
		{
			name: "missing party key",
			mutate: func(start *SessionStart) {
				start.Participants[0].PartyKey = nil
			},
			wantErr: ErrMissingPartyKey,
		},
		{
			name: "missing identity public key",
			mutate: func(start *SessionStart) {
				start.Participants[0].IdentityPublicKey = nil
			},
			wantErr: ErrMissingIdentityPublicKey,
		},
		{
			name: "invalid threshold",
			mutate: func(start *SessionStart) {
				start.Threshold = 3
			},
			wantErr: ErrInvalidThreshold,
		},
		{
			name: "missing sign input",
			mutate: func(start *SessionStart) {
				start.Operation = OperationTypeSign
				start.Keygen = nil
				start.Sign = &SignPayload{KeyID: "key-1"}
			},
			wantErr: ErrInvalidPayload,
		},
		{
			name: "eddsa derivation unsupported",
			mutate: func(start *SessionStart) {
				start.Protocol = ProtocolTypeEdDSA
				start.Operation = OperationTypeSign
				start.Keygen = nil
				start.Sign = &SignPayload{KeyID: "key-1", SigningInput: []byte("msg"), Derivation: &NonHardenedDerivation{Delta: []byte{1}}}
			},
			wantErr: ErrUnsupportedDerivationOnAlgo,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			start := validSessionStart()
			tt.mutate(start)
			err := ValidateSessionStart(start)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("ValidateSessionStart() unexpected error = %v", err)
			}
			if tt.wantErr != nil && !isErr(err, tt.wantErr) {
				t.Fatalf("ValidateSessionStart() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateControlMessage(t *testing.T) {
	t.Parallel()

	message := &ControlMessage{
		SessionID:     "session-1",
		CoordinatorID: "coordinator-1",
		Sequence:      1,
		Signature:     []byte{1},
		SessionStart:  validSessionStart(),
	}
	if err := ValidateControlMessage(message); err != nil {
		t.Fatalf("ValidateControlMessage() error = %v", err)
	}

	message.SessionID = "other-session"
	if err := ValidateControlMessage(message); !isErr(err, ErrInvalidControlMessageBody) {
		t.Fatalf("ValidateControlMessage() error = %v, want %v", err, ErrInvalidControlMessageBody)
	}

	keyExchange := &ControlMessage{
		SessionID:     "session-1",
		CoordinatorID: "coordinator-1",
		Sequence:      2,
		Signature:     []byte{1},
		KeyExchange:   &KeyExchangeBegin{ExchangeID: "kx-1"},
	}
	if err := ValidateControlMessage(keyExchange); err != nil {
		t.Fatalf("ValidateControlMessage(key exchange) error = %v", err)
	}
	keyExchange.KeyExchange.ExchangeID = ""
	if err := ValidateControlMessage(keyExchange); !isErr(err, ErrInvalidControlMessageBody) {
		t.Fatalf("ValidateControlMessage(missing exchange id) error = %v", err)
	}
}

func TestValidatePeerMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		msg     *PeerMessage
		wantErr error
	}{
		{
			name: "valid key exchange hello",
			msg: &PeerMessage{
				SessionID:         "session-1",
				Sequence:          1,
				FromParticipantID: "p1",
				ToParticipantID:   "p2",
				Phase:             ParticipantPhaseKeyExchange,
				Signature:         []byte{1},
				KeyExchangeHello:  &KeyExchangeHello{ExchangeID: "kx-1", X25519PublicKey: []byte{1, 2, 3}},
			},
		},
		{
			name: "missing signature",
			msg: &PeerMessage{
				SessionID:         "session-1",
				Sequence:          1,
				FromParticipantID: "p1",
				Broadcast:         true,
				Phase:             ParticipantPhaseMPCRunning,
				MPCPacket:         &MPCPacket{Payload: []byte{1}, Nonce: []byte{}},
			},
			wantErr: ErrMissingSignature,
		},
		{
			name: "direct packet missing recipient",
			msg: &PeerMessage{
				SessionID:         "session-1",
				Sequence:          1,
				FromParticipantID: "p1",
				Phase:             ParticipantPhaseMPCRunning,
				Signature:         []byte{1},
				MPCPacket:         &MPCPacket{Payload: []byte{1}},
			},
			wantErr: ErrInvalidRouting,
		},
		{
			name: "direct packet missing nonce",
			msg: &PeerMessage{
				SessionID:         "session-1",
				Sequence:          1,
				FromParticipantID: "p1",
				ToParticipantID:   "p2",
				Phase:             ParticipantPhaseMPCRunning,
				Signature:         []byte{1},
				MPCPacket:         &MPCPacket{Payload: []byte{1}},
			},
			wantErr: ErrInvalidRouting,
		},
		{
			name: "broadcast packet is rejected",
			msg: &PeerMessage{
				SessionID:         "session-1",
				Sequence:          1,
				FromParticipantID: "p1",
				Broadcast:         true,
				Phase:             ParticipantPhaseMPCRunning,
				Signature:         []byte{1},
				MPCPacket:         &MPCPacket{Payload: []byte{1}, Nonce: []byte{1}},
			},
			wantErr: ErrInvalidRouting,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePeerMessage(tt.msg)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("ValidatePeerMessage() unexpected error = %v", err)
			}
			if tt.wantErr != nil && !isErr(err, tt.wantErr) {
				t.Fatalf("ValidatePeerMessage() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSigningBytesDeterministic(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := &PeerMessage{
		SessionID:         "session-1",
		Sequence:          1,
		FromParticipantID: "p1",
		ToParticipantID:   "p2",
		Phase:             ParticipantPhaseMPCRunning,
		Signature:         []byte("ignored"),
		MPCPacket:         &MPCPacket{Payload: []byte("payload"), Nonce: []byte("nonce")},
	}

	first, err := PeerSigningBytes(message)
	if err != nil {
		t.Fatalf("PeerSigningBytes() error = %v", err)
	}
	second, err := PeerSigningBytes(message)
	if err != nil {
		t.Fatalf("PeerSigningBytes() second error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("PeerSigningBytes() mismatch between deterministic marshals")
	}

	sig := ed25519.Sign(priv, first)
	if !ed25519.Verify(pub, second, sig) {
		t.Fatalf("Verify() returned false")
	}
}

func validSessionStart() *SessionStart {
	return &SessionStart{
		SessionID: "session-1",
		Protocol:  ProtocolTypeECDSA,
		Operation: OperationTypeKeygen,
		Threshold: 1,
		Participants: []*SessionParticipant{
			{ParticipantID: "p1", PartyKey: []byte{1}, IdentityPublicKey: []byte{11}},
			{ParticipantID: "p2", PartyKey: []byte{2}, IdentityPublicKey: []byte{22}},
		},
		Keygen: &KeygenPayload{KeyID: "key-1"},
	}
}

func TestValidateSessionEvent(t *testing.T) {
	t.Parallel()

	valid := &SessionEvent{
		SessionID:     "session-1",
		ParticipantID: "p1",
		Sequence:      1,
		Signature:     []byte{1},
		PeerReady:     &PeerReady{ParticipantID: "p1"},
	}
	if err := ValidateSessionEvent(valid); err != nil {
		t.Fatalf("ValidateSessionEvent() error = %v", err)
	}

	invalid := *valid
	invalid.Signature = nil
	if err := ValidateSessionEvent(&invalid); !isErr(err, ErrMissingSignature) {
		t.Fatalf("ValidateSessionEvent() error = %v, want %v", err, ErrMissingSignature)
	}
}

func TestValidatePresenceEvent(t *testing.T) {
	t.Parallel()

	valid := &PresenceEvent{
		PeerID:         "peer-1",
		Status:         PresenceStatusOnline,
		Transport:      TransportTypeNATS,
		ConnectionID:   "conn-1",
		LastSeenUnixMs: 1,
	}
	if err := ValidatePresenceEvent(valid); err != nil {
		t.Fatalf("ValidatePresenceEvent() error = %v", err)
	}

	invalid := *valid
	invalid.ConnectionID = ""
	if err := ValidatePresenceEvent(&invalid); !isErr(err, ErrInvalidPayload) {
		t.Fatalf("ValidatePresenceEvent() error = %v, want %v", err, ErrInvalidPayload)
	}
}

func isErr(err error, want error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, want) || strings.Contains(err.Error(), want.Error())
}
