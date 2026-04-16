package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestValidateSessionStart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(start *SessionStart)
		wantErr error
	}{
		{
			name:    "valid keygen",
			mutate:  func(*SessionStart) {},
			wantErr: nil,
		},
		{
			name: "duplicate participant id",
			mutate: func(start *SessionStart) {
				start.Participants[1].ParticipantId = start.Participants[0].ParticipantId
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
			name: "invalid threshold",
			mutate: func(start *SessionStart) {
				start.Threshold = 3
			},
			wantErr: ErrInvalidThreshold,
		},
		{
			name: "missing sign input",
			mutate: func(start *SessionStart) {
				start.Operation = OperationType_OPERATION_TYPE_SIGN
				start.Payload = &SessionStart_Sign{
					Sign: &SignPayload{KeyId: "key-1"},
				}
			},
			wantErr: ErrInvalidPayload,
		},
		{
			name: "eddsa derivation unsupported",
			mutate: func(start *SessionStart) {
				start.Protocol = ProtocolType_PROTOCOL_TYPE_EDDSA
				start.Operation = OperationType_OPERATION_TYPE_SIGN
				start.Payload = &SessionStart_Sign{
					Sign: &SignPayload{
						KeyId:        "key-1",
						SigningInput: []byte("msg"),
						Derivation: &NonHardenedDerivation{
							Delta: []byte{1},
						},
					},
				}
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
		SessionId:     "session-1",
		CoordinatorId: "coordinator-1",
		Sequence:      1,
		Signature:     []byte{1},
		Body: &ControlMessage_SessionStart{
			SessionStart: validSessionStart(),
		},
	}
	if err := ValidateControlMessage(message); err != nil {
		t.Fatalf("ValidateControlMessage() error = %v", err)
	}

	message.SessionId = "other-session"
	if err := ValidateControlMessage(message); !isErr(err, ErrInvalidControlMessageBody) {
		t.Fatalf("ValidateControlMessage() error = %v, want %v", err, ErrInvalidControlMessageBody)
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
				SessionId:         "session-1",
				Sequence:          1,
				FromParticipantId: "p1",
				ToParticipantId:   "p2",
				Phase:             ParticipantPhase_PARTICIPANT_PHASE_KEY_EXCHANGE,
				Signature:         []byte{1},
				Body: &PeerMessage_KeyExchangeHello{
					KeyExchangeHello: &KeyExchangeHello{X25519PublicKey: []byte{1, 2, 3}},
				},
			},
		},
		{
			name: "missing signature on broadcast",
			msg: &PeerMessage{
				SessionId:         "session-1",
				Sequence:          1,
				FromParticipantId: "p1",
				Broadcast:         true,
				Phase:             ParticipantPhase_PARTICIPANT_PHASE_MPC_RUNNING,
				Body: &PeerMessage_MpcPacket{
					MpcPacket: &MpcPacket{Payload: []byte{1}},
				},
			},
			wantErr: ErrMissingSignature,
		},
		{
			name: "direct packet missing nonce",
			msg: &PeerMessage{
				SessionId:         "session-1",
				Sequence:          1,
				FromParticipantId: "p1",
				ToParticipantId:   "p2",
				Phase:             ParticipantPhase_PARTICIPANT_PHASE_MPC_RUNNING,
				Body: &PeerMessage_MpcPacket{
					MpcPacket: &MpcPacket{Payload: []byte{1}},
				},
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
		SessionId:         "session-1",
		Sequence:          1,
		FromParticipantId: "p1",
		Broadcast:         true,
		Phase:             ParticipantPhase_PARTICIPANT_PHASE_MPC_RUNNING,
		Signature:         []byte("ignored"),
		Body: &PeerMessage_MpcPacket{
			MpcPacket: &MpcPacket{Payload: []byte("payload")},
		},
	}

	first, err := PeerSigningBytes(message)
	if err != nil {
		t.Fatalf("PeerSigningBytes() error = %v", err)
	}
	second, err := PeerSigningBytes(proto.Clone(message).(*PeerMessage))
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
		SessionId: "session-1",
		Protocol:  ProtocolType_PROTOCOL_TYPE_ECDSA,
		Operation: OperationType_OPERATION_TYPE_KEYGEN,
		Threshold: 1,
		Participants: []*SessionParticipant{
			{ParticipantId: "p1", PartyKey: []byte{1}},
			{ParticipantId: "p2", PartyKey: []byte{2}},
		},
		Payload: &SessionStart_Keygen{
			Keygen: &KeygenPayload{KeyId: "key-1"},
		},
	}
}

func isErr(err error, want error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, want) || strings.Contains(err.Error(), want.Error())
}
