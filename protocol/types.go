package protocol

import "encoding/json"

type ProtocolType string

const (
	ProtocolTypeUnspecified ProtocolType = "UNSPECIFIED"
	ProtocolTypeECDSA       ProtocolType = "ECDSA"
	ProtocolTypeEdDSA       ProtocolType = "EdDSA"
)

type OperationType string

const (
	OperationTypeUnspecified OperationType = "UNSPECIFIED"
	OperationTypeKeygen      OperationType = "KEYGEN"
	OperationTypeSign        OperationType = "SIGN"
	OperationTypeReshare     OperationType = "RESHARE"
)

type ParticipantPhase string

const (
	ParticipantPhaseUnspecified     ParticipantPhase = "UNSPECIFIED"
	ParticipantPhaseCreated         ParticipantPhase = "CREATED"
	ParticipantPhaseJoining         ParticipantPhase = "JOINING"
	ParticipantPhaseReady           ParticipantPhase = "READY"
	ParticipantPhaseKeyExchange     ParticipantPhase = "KEY_EXCHANGE"
	ParticipantPhaseKeyExchangeDone ParticipantPhase = "KEY_EXCHANGE_DONE"
	ParticipantPhaseMPCRunning      ParticipantPhase = "MPC_RUNNING"
	ParticipantPhaseCompleted       ParticipantPhase = "COMPLETED"
	ParticipantPhaseFailed          ParticipantPhase = "FAILED"
	ParticipantPhaseAborted         ParticipantPhase = "ABORTED"
)

type FailureReason string

const (
	FailureReasonUnspecified          FailureReason = "UNSPECIFIED"
	FailureReasonInvalidSession       FailureReason = "INVALID_SESSION"
	FailureReasonInvalidMessage       FailureReason = "INVALID_MESSAGE"
	FailureReasonInvalidSignature     FailureReason = "INVALID_SIGNATURE"
	FailureReasonDecryptFailed        FailureReason = "DECRYPT_FAILED"
	FailureReasonUnsupportedOperation FailureReason = "UNSUPPORTED_OPERATION"
	FailureReasonMissingPrerequisite  FailureReason = "MISSING_PREREQUISITE"
	FailureReasonTSSError             FailureReason = "TSS_ERROR"
	FailureReasonAborted              FailureReason = "ABORTED"
	FailureReasonTimeout              FailureReason = "TIMEOUT"
	FailureReasonReplay               FailureReason = "REPLAY"
)

type SessionParticipant struct {
	ParticipantID     string `json:"participant_id"`
	PartyKey          []byte `json:"party_key"`
	IdentityPublicKey []byte `json:"identity_public_key,omitempty"`
}

type NonHardenedDerivation struct {
	Path  []uint32 `json:"path,omitempty"`
	Delta []byte   `json:"delta,omitempty"`
}

type KeygenPayload struct {
	KeyID string `json:"key_id"`
}

type SignPayload struct {
	KeyID        string                 `json:"key_id"`
	SigningInput []byte                 `json:"signing_input"`
	Derivation   *NonHardenedDerivation `json:"derivation,omitempty"`
}

type ResharePayload struct {
	KeyID           string                `json:"key_id"`
	NewThreshold    uint32                `json:"new_threshold"`
	NewParticipants []*SessionParticipant `json:"new_participants,omitempty"`
}

type SessionStart struct {
	SessionID    string                `json:"session_id"`
	Protocol     ProtocolType          `json:"protocol"`
	Operation    OperationType         `json:"operation"`
	Threshold    uint32                `json:"threshold"`
	Participants []*SessionParticipant `json:"participants"`
	Keygen       *KeygenPayload        `json:"keygen,omitempty"`
	Sign         *SignPayload          `json:"sign,omitempty"`
	Reshare      *ResharePayload       `json:"reshare,omitempty"`
}

type KeyExchangeBegin struct {
	ExchangeID string `json:"exchange_id"`
}

type MPCBegin struct{}

type SessionAbort struct {
	Reason FailureReason `json:"reason"`
	Detail string        `json:"detail,omitempty"`
}

type ControlMessage struct {
	SessionID     string            `json:"session_id"`
	Sequence      uint64            `json:"sequence"`
	CoordinatorID string            `json:"coordinator_id"`
	Signature     []byte            `json:"signature,omitempty"`
	SessionStart  *SessionStart     `json:"session_start,omitempty"`
	KeyExchange   *KeyExchangeBegin `json:"key_exchange_begin,omitempty"`
	MPCBegin      *MPCBegin         `json:"mpc_begin,omitempty"`
	SessionAbort  *SessionAbort     `json:"session_abort,omitempty"`
}

type KeyExchangeHello struct {
	ExchangeID      string `json:"exchange_id"`
	X25519PublicKey []byte `json:"x25519_public_key"`
}

type MPCPacket struct {
	Payload []byte `json:"payload"`
	Nonce   []byte `json:"nonce,omitempty"`
}

type PeerMessage struct {
	SessionID         string            `json:"session_id"`
	Sequence          uint64            `json:"sequence"`
	FromParticipantID string            `json:"from_participant_id"`
	ToParticipantID   string            `json:"to_participant_id,omitempty"`
	Broadcast         bool              `json:"broadcast,omitempty"`
	Phase             ParticipantPhase  `json:"phase"`
	Signature         []byte            `json:"signature,omitempty"`
	KeyExchangeHello  *KeyExchangeHello `json:"key_exchange_hello,omitempty"`
	MPCPacket         *MPCPacket        `json:"mpc_packet,omitempty"`
}

type KeyShareResult struct {
	KeyID       string `json:"key_id"`
	ShareBlob   []byte `json:"share_blob,omitempty"`
	PublicKey   []byte `json:"public_key,omitempty"`
	ECDSAPubKey []byte `json:"ecdsa_pubkey,omitempty"`
	EDDSAPubKey []byte `json:"eddsa_pubkey,omitempty"`
}

type SignatureResult struct {
	KeyID             string `json:"key_id"`
	Signature         []byte `json:"signature,omitempty"`
	SignatureRecovery []byte `json:"signature_recovery,omitempty"`
	R                 []byte `json:"r,omitempty"`
	S                 []byte `json:"s,omitempty"`
	SignedInput       []byte `json:"signed_input,omitempty"`
	PublicKey         []byte `json:"public_key,omitempty"`
}

type Result struct {
	KeyShare  *KeyShareResult  `json:"key_share,omitempty"`
	Signature *SignatureResult `json:"signature,omitempty"`
}

type PeerJoined struct {
	ParticipantID string `json:"participant_id"`
}

type PeerReady struct {
	ParticipantID string `json:"participant_id"`
}

type PeerKeyExchangeDone struct {
	ParticipantID string `json:"participant_id"`
}

type PeerFailed struct {
	ParticipantID string        `json:"participant_id"`
	Reason        FailureReason `json:"reason"`
	Detail        string        `json:"detail,omitempty"`
}

type SessionCompleted struct {
	Result *Result `json:"result,omitempty"`
}

type SessionFailed struct {
	Reason FailureReason `json:"reason"`
	Detail string        `json:"detail,omitempty"`
}

type SessionEvent struct {
	SessionID           string               `json:"session_id"`
	ParticipantID       string               `json:"participant_id"`
	Sequence            uint64               `json:"sequence"`
	Signature           []byte               `json:"signature,omitempty"`
	PeerJoined          *PeerJoined          `json:"peer_joined,omitempty"`
	PeerReady           *PeerReady           `json:"peer_ready,omitempty"`
	PeerKeyExchangeDone *PeerKeyExchangeDone `json:"peer_key_exchange_done,omitempty"`
	PeerFailed          *PeerFailed          `json:"peer_failed,omitempty"`
	SessionCompleted    *SessionCompleted    `json:"session_completed,omitempty"`
	SessionFailed       *SessionFailed       `json:"session_failed,omitempty"`
}

type PresenceStatus string

const (
	PresenceStatusUnspecified PresenceStatus = "UNSPECIFIED"
	PresenceStatusOnline      PresenceStatus = "ONLINE"
	PresenceStatusOffline     PresenceStatus = "OFFLINE"
)

type TransportType string

const (
	TransportTypeUnspecified TransportType = "UNSPECIFIED"
	TransportTypeNATS        TransportType = "NATS"
	TransportTypeMQTT        TransportType = "MQTT"
)

type PresenceEvent struct {
	PeerID         string         `json:"peer_id"`
	Status         PresenceStatus `json:"status"`
	Transport      TransportType  `json:"transport"`
	ConnectionID   string         `json:"connection_id,omitempty"`
	LastSeenUnixMs int64          `json:"last_seen_unix_ms"`
}

type RequestAccepted struct {
	Accepted  bool   `json:"accepted"`
	SessionID string `json:"session_id"`
	ExpiresAt string `json:"expires_at"`
}

type RequestRejected struct {
	Accepted     bool   `json:"accepted"`
	ErrorCode    string `json:"error_code"`
	ErrorMessage string `json:"error_message"`
}

func MarshalJSON(msg any) ([]byte, error) {
	return json.Marshal(msg)
}

func UnmarshalJSON(data []byte, dst any) error {
	return json.Unmarshal(data, dst)
}
