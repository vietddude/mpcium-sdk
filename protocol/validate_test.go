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
		{
			name: "valid signing context",
			mutate: func(start *SessionStart) {
				start.Operation = OperationTypeSign
				start.Keygen = nil
				start.Sign = &SignPayload{
					KeyID:          "key-1",
					SigningInput:   []byte("msg"),
					SigningContext: []byte(`{"version":1,"tx":{"verified":true}}`),
				}
			},
			wantErr: nil,
		},
		{
			name: "invalid signing context json",
			mutate: func(start *SessionStart) {
				start.Operation = OperationTypeSign
				start.Keygen = nil
				start.Sign = &SignPayload{
					KeyID:          "key-1",
					SigningInput:   []byte("msg"),
					SigningContext: []byte(`{"version":`),
				}
			},
			wantErr: ErrInvalidSigningContext,
		},
		{
			name: "oversized signing context",
			mutate: func(start *SessionStart) {
				start.Operation = OperationTypeSign
				start.Keygen = nil
				start.Sign = &SignPayload{
					KeyID:          "key-1",
					SigningInput:   []byte("msg"),
					SigningContext: append([]byte(`{"value":"`), append(make([]byte, MaxSigningContextBytes), []byte(`"}`)...)...),
				}
			},
			wantErr: ErrSigningContextTooLarge,
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

func TestProtocolHelpers(t *testing.T) {
	tests := []struct {
		name        string
		in          ProtocolType
		normalized  ProtocolType
		unspecified bool
		concrete    bool
	}{
		{name: "empty", in: "", normalized: ProtocolTypeUnspecified, unspecified: true},
		{name: "whitespace", in: "   ", normalized: ProtocolTypeUnspecified, unspecified: true},
		{name: "unspecified", in: ProtocolTypeUnspecified, normalized: ProtocolTypeUnspecified, unspecified: true},
		{name: "ecdsa", in: ProtocolTypeECDSA, normalized: ProtocolTypeECDSA, concrete: true},
		{name: "eddsa", in: ProtocolTypeEdDSA, normalized: ProtocolTypeEdDSA, concrete: true},
		{name: "both", in: ProtocolType("both"), normalized: ProtocolTypeBoth},
		{name: "trimmed both", in: ProtocolType(" both "), normalized: ProtocolTypeBoth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeProtocol(tt.in); got != tt.normalized {
				t.Fatalf("NormalizeProtocol() = %q, want %q", got, tt.normalized)
			}
			if got := IsProtocolUnspecified(tt.in); got != tt.unspecified {
				t.Fatalf("IsProtocolUnspecified() = %v, want %v", got, tt.unspecified)
			}
			if got := IsConcreteProtocol(tt.in); got != tt.concrete {
				t.Fatalf("IsConcreteProtocol() = %v, want %v", got, tt.concrete)
			}
			if got := IsDualProtocol(tt.in); got != (tt.normalized == ProtocolTypeBoth) {
				t.Fatalf("IsDualProtocol() = %v", got)
			}
		})
	}
}

func TestCloneSessionStartDeepCopiesWireFields(t *testing.T) {
	start := &SessionStart{
		SessionID: "sess-1",
		Protocol:  ProtocolTypeECDSA,
		Operation: OperationTypeSign,
		Threshold: 1,
		Participants: []*SessionParticipant{
			{ParticipantID: "p1", PartyKey: []byte("party-1"), IdentityPublicKey: []byte("identity-1")},
			{ParticipantID: "p2", PartyKey: []byte("party-2"), IdentityPublicKey: []byte("identity-2")},
		},
		Sign: &SignPayload{
			KeyID:        "wallet-1",
			SigningInput: []byte("message"),
			SigningContext: []byte(
				`{"version":1,"tx":{"verified":true}}`,
			),
			Derivation: &NonHardenedDerivation{
				Path:  []uint32{1, 2},
				Delta: []byte("delta"),
			},
		},
	}

	cloned := CloneSessionStart(start)
	if cloned == nil {
		t.Fatalf("CloneSessionStart() returned nil")
	}

	start.Participants[0].PartyKey[0] = 'X'
	start.Participants[0].IdentityPublicKey[0] = 'Y'
	start.Sign.SigningInput[0] = 'Z'
	start.Sign.SigningContext[0] = '['
	start.Sign.Derivation.Path[0] = 99
	start.Sign.Derivation.Delta[0] = 'Q'

	if string(cloned.Participants[0].PartyKey) != "party-1" {
		t.Fatalf("party key was not deep copied: %q", string(cloned.Participants[0].PartyKey))
	}
	if string(cloned.Participants[0].IdentityPublicKey) != "identity-1" {
		t.Fatalf("identity key was not deep copied: %q", string(cloned.Participants[0].IdentityPublicKey))
	}
	if string(cloned.Sign.SigningInput) != "message" {
		t.Fatalf("signing input was not deep copied: %q", string(cloned.Sign.SigningInput))
	}
	if string(cloned.Sign.SigningContext) != `{"version":1,"tx":{"verified":true}}` {
		t.Fatalf("signing context was not deep copied: %q", string(cloned.Sign.SigningContext))
	}
	if cloned.Sign.Derivation.Path[0] != 1 {
		t.Fatalf("derivation path was not deep copied: %+v", cloned.Sign.Derivation.Path)
	}
	if string(cloned.Sign.Derivation.Delta) != "delta" {
		t.Fatalf("derivation delta was not deep copied: %q", string(cloned.Sign.Derivation.Delta))
	}
}

func TestCloneProtocolResultDeepCopiesWireFields(t *testing.T) {
	keyShare := &Result{KeyShare: &KeyShareResult{
		KeyID:     "wallet-1",
		ShareBlob: []byte("share"),
		PublicKey: []byte("public"),
	}}
	clonedKeyShare := CloneProtocolResult(keyShare)
	keyShare.KeyShare.ShareBlob[0] = 'X'
	keyShare.KeyShare.PublicKey[0] = 'Y'
	if string(clonedKeyShare.KeyShare.ShareBlob) != "share" {
		t.Fatalf("share blob was not deep copied: %q", string(clonedKeyShare.KeyShare.ShareBlob))
	}
	if string(clonedKeyShare.KeyShare.PublicKey) != "public" {
		t.Fatalf("public key was not deep copied: %q", string(clonedKeyShare.KeyShare.PublicKey))
	}

	signature := &Result{Signature: &SignatureResult{
		KeyID:             "wallet-1",
		Signature:         []byte("signature"),
		SignatureRecovery: []byte("recovery"),
		R:                 []byte("r"),
		S:                 []byte("s"),
		SignedInput:       []byte("input"),
		PublicKey:         []byte("pub"),
	}}
	clonedSignature := CloneProtocolResult(signature)
	signature.Signature.Signature[0] = 'X'
	signature.Signature.SignatureRecovery[0] = 'Y'
	signature.Signature.R[0] = 'Z'
	signature.Signature.S[0] = 'Q'
	signature.Signature.SignedInput[0] = 'W'
	signature.Signature.PublicKey[0] = 'V'
	if string(clonedSignature.Signature.Signature) != "signature" {
		t.Fatalf("signature was not deep copied: %q", string(clonedSignature.Signature.Signature))
	}
	if string(clonedSignature.Signature.SignatureRecovery) != "recovery" {
		t.Fatalf("signature recovery was not deep copied: %q", string(clonedSignature.Signature.SignatureRecovery))
	}
	if string(clonedSignature.Signature.R) != "r" || string(clonedSignature.Signature.S) != "s" {
		t.Fatalf("signature scalars were not deep copied: r=%q s=%q", string(clonedSignature.Signature.R), string(clonedSignature.Signature.S))
	}
	if string(clonedSignature.Signature.SignedInput) != "input" {
		t.Fatalf("signed input was not deep copied: %q", string(clonedSignature.Signature.SignedInput))
	}
	if string(clonedSignature.Signature.PublicKey) != "pub" {
		t.Fatalf("public key was not deep copied: %q", string(clonedSignature.Signature.PublicKey))
	}
}

func TestValidateControlMessage(t *testing.T) {
	t.Parallel()

	message := &ControlMessage{
		SessionID:      "session-1",
		OrchestratorID: "orch-1",
		Sequence:       1,
		Signature:      []byte{1},
		SessionStart:   validSessionStart(),
	}
	if err := ValidateControlMessage(message); err != nil {
		t.Fatalf("ValidateControlMessage() error = %v", err)
	}

	message.SessionID = "other-session"
	if err := ValidateControlMessage(message); !isErr(err, ErrInvalidControlMessageBody) {
		t.Fatalf("ValidateControlMessage() error = %v, want %v", err, ErrInvalidControlMessageBody)
	}

	keyExchange := &ControlMessage{
		SessionID:      "session-1",
		OrchestratorID: "orch-1",
		Sequence:       2,
		Signature:      []byte{1},
		KeyExchange:    &KeyExchangeBegin{ExchangeID: "kx-1"},
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

func TestControlSignatureCoversSigningContext(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	start := validSessionStart()
	start.Operation = OperationTypeSign
	start.Keygen = nil
	start.Sign = &SignPayload{
		KeyID:          "key-1",
		SigningInput:   []byte("message"),
		SigningContext: []byte(`{"version":1,"tx":{"verified":true}}`),
	}
	message := &ControlMessage{
		SessionID:      start.SessionID,
		OrchestratorID: "orch-1",
		SessionStart:   start,
	}
	signedBytes, err := ControlSigningBytes(message)
	if err != nil {
		t.Fatalf("ControlSigningBytes() error = %v", err)
	}
	signature := ed25519.Sign(priv, signedBytes)

	message.SessionStart.Sign.SigningContext = []byte(`{"version":1,"tx":{"verified":false}}`)
	tamperedBytes, err := ControlSigningBytes(message)
	if err != nil {
		t.Fatalf("ControlSigningBytes() after tamper error = %v", err)
	}
	if ed25519.Verify(pub, tamperedBytes, signature) {
		t.Fatal("signature remained valid after signing context tamper")
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
		ParticipantID:  "peer-1",
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
