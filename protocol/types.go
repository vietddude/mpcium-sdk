package protocol

import "encoding/json"

// ProtocolType selects the threshold signature scheme to run.
type ProtocolType string

const (
	ProtocolTypeUnspecified ProtocolType = "UNSPECIFIED"
	ProtocolTypeECDSA       ProtocolType = "ECDSA"
	ProtocolTypeEdDSA       ProtocolType = "EdDSA"
)

// OperationType identifies what a session is doing (keygen, signing, or reshare).
type OperationType string

const (
	OperationTypeUnspecified OperationType = "UNSPECIFIED"
	OperationTypeKeygen      OperationType = "KEYGEN"
	OperationTypeSign        OperationType = "SIGN"
	OperationTypeReshare     OperationType = "RESHARE"
)

// ParticipantPhase is the local lifecycle state of a participant within a
// session. It is stamped on every outbound PeerMessage so peers and the
// coordinator can reason about progress and ordering.
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

// FailureReason categorises why a session or participant aborted/failed.
// It is carried on SessionAbort, PeerFailed, and SessionFailed bodies.
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

// SessionParticipant describes one party in an MPC session: its logical ID,
// the tss-lib ordering token (PartyKey), and the ed25519 identity key used
// to verify its signed messages.
type SessionParticipant struct {
	ParticipantID string `json:"participant_id"`
	// PartyKey is the tss-lib ordering token for this participant.
	// It is NOT a cryptographic key. It is SHA-256'd with ParticipantID
	// to derive the *big.Int used by tss.SortPartyIDs, so all parties
	// agree on a deterministic round ordering. Must be non-empty,
	// unique within a session, and stable across keygen/sign/reshare
	// for the same logical participant. A safe choice is the
	// participant's ed25519 public key bytes.
	PartyKey          []byte `json:"party_key"`
	IdentityPublicKey []byte `json:"identity_public_key,omitempty"`
}

// NonHardenedDerivation describes an optional BIP32-style non-hardened
// child derivation to apply during an ECDSA signing session. Path is the
// child index chain; Delta is the precomputed tweak scalar. EdDSA sessions
// do not support derivation.
type NonHardenedDerivation struct {
	Path  []uint32 `json:"path,omitempty"`
	Delta []byte   `json:"delta,omitempty"`
}

// KeygenPayload is the operation-specific body carried by SessionStart
// when Operation == KEYGEN. KeyID is the logical identifier the resulting
// key share will be stored under.
type KeygenPayload struct {
	KeyID string `json:"key_id"`
}

// SignPayload is the operation-specific body carried by SessionStart when
// Operation == SIGN. It names the existing key to sign with, the bytes to
// sign, and an optional non-hardened derivation (ECDSA only).
type SignPayload struct {
	KeyID        string                 `json:"key_id"`
	SigningInput []byte                 `json:"signing_input"`
	Derivation   *NonHardenedDerivation `json:"derivation,omitempty"`
}

// ResharePayload is the operation-specific body carried by SessionStart
// when Operation == RESHARE. It identifies the key to reshare and
// describes the new committee/threshold.
type ResharePayload struct {
	KeyID           string                `json:"key_id"`
	NewThreshold    uint32                `json:"new_threshold"`
	NewParticipants []*SessionParticipant `json:"new_participants,omitempty"`
}

// SessionStart is the coordinator-authored message that defines a new MPC
// session: which protocol/operation, the threshold, and the participant
// committee. Exactly one of Keygen/Sign/Reshare must be set to match
// Operation. It is delivered inside a signed ControlMessage.
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

// KeyExchangeBegin is the coordinator command that tells participants to
// start an X25519 key exchange round under ExchangeID; peers then emit
// KeyExchangeHello messages tagged with this ID.
type KeyExchangeBegin struct {
	ExchangeID string `json:"exchange_id"`
}

// MPCBegin is the coordinator command that tells participants to start
// running tss-lib rounds. It must arrive after key exchange is complete;
// otherwise the session fails with a missing-prerequisite error.
type MPCBegin struct{}

// SessionAbort is the coordinator command that terminates an in-flight
// session with the given reason/detail.
type SessionAbort struct {
	Reason FailureReason `json:"reason"`
	Detail string        `json:"detail,omitempty"`
}

// ControlMessage is the signed, coordinator-to-participant envelope that
// drives a session forward. Exactly one body (SessionStart, KeyExchange,
// MPCBegin, SessionAbort) is set per message; the transport must verify
// Signature against the coordinator's identity key.
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

// KeyExchangeHello is the peer-to-peer X25519 public key advertisement
// that peers exchange under an ExchangeID. The resulting shared secrets
// are used to encrypt direct MPCPackets for the rest of the session.
type KeyExchangeHello struct {
	ExchangeID      string `json:"exchange_id"`
	X25519PublicKey []byte `json:"x25519_public_key"`
}

// MPCPacket carries one tss-lib round payload. For direct (unicast)
// messages Payload is AEAD-encrypted and Nonce is required; for broadcast
// messages Payload is plaintext-signed and Nonce must be empty.
type MPCPacket struct {
	Payload []byte `json:"payload"`
	Nonce   []byte `json:"nonce,omitempty"`
}

// PeerMessage is the signed participant-to-participant envelope used for
// both key exchange and MPC rounds. Exactly one body (KeyExchangeHello or
// MPCPacket) is set. Routing rules: direct messages set ToParticipantID
// and Broadcast=false; broadcast messages leave ToParticipantID empty.
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

// KeyShareResult is the terminal output of a successful KEYGEN session:
// the opaque local share blob (caller-encrypted at rest) and the joint
// public key for the generated key.
type KeyShareResult struct {
	KeyID     string `json:"key_id"`
	ShareBlob []byte `json:"share_blob,omitempty"`
	PublicKey []byte `json:"public_key,omitempty"`
}

// SignatureResult is the terminal output of a successful SIGN session.
// Signature holds the canonical encoded form; R/S (ECDSA) and
// SignatureRecovery (ECDSA recovery id) are populated for callers that
// need the scalar components.
type SignatureResult struct {
	KeyID             string `json:"key_id"`
	Signature         []byte `json:"signature,omitempty"`
	SignatureRecovery []byte `json:"signature_recovery,omitempty"`
	R                 []byte `json:"r,omitempty"`
	S                 []byte `json:"s,omitempty"`
	SignedInput       []byte `json:"signed_input,omitempty"`
	PublicKey         []byte `json:"public_key,omitempty"`
}

// Result is the terminal session output handed back to the integrator.
// Exactly one of KeyShare or Signature is set, matching the session's
// Operation.
type Result struct {
	KeyShare  *KeyShareResult  `json:"key_share,omitempty"`
	Signature *SignatureResult `json:"signature,omitempty"`
}

// PeerJoined notifies that a participant has joined the session.
type PeerJoined struct {
	ParticipantID string `json:"participant_id"`
}

// PeerReady notifies that a participant has finished local setup and is
// ready to proceed with key exchange.
type PeerReady struct {
	ParticipantID string `json:"participant_id"`
}

// PeerKeyExchangeDone notifies that a participant has completed the
// X25519 key exchange round and is ready for MPCBegin.
type PeerKeyExchangeDone struct {
	ParticipantID string `json:"participant_id"`
}

// PeerFailed notifies that a single participant has failed; the session
// as a whole may or may not still be recoverable depending on threshold.
type PeerFailed struct {
	ParticipantID string        `json:"participant_id"`
	Reason        FailureReason `json:"reason"`
	Detail        string        `json:"detail,omitempty"`
}

// SessionCompleted is the terminal event carrying the final Result.
type SessionCompleted struct {
	Result *Result `json:"result,omitempty"`
}

// SessionFailed is the terminal event emitted when the session cannot
// produce a result.
type SessionFailed struct {
	Reason FailureReason `json:"reason"`
	Detail string        `json:"detail,omitempty"`
}

// SessionEvent is the signed out-of-band notification emitted by a
// participant to the coordinator/observers about lifecycle transitions
// and terminal results. Exactly one body field is set per event.
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

// PresenceStatus reports whether a peer is currently reachable on the
// transport. It is independent of any specific session.
type PresenceStatus string

const (
	PresenceStatusUnspecified PresenceStatus = "UNSPECIFIED"
	PresenceStatusOnline      PresenceStatus = "ONLINE"
	PresenceStatusOffline     PresenceStatus = "OFFLINE"
)

// TransportType identifies the underlying messaging transport a peer is
// connected through.
type TransportType string

const (
	TransportTypeUnspecified TransportType = "UNSPECIFIED"
	TransportTypeNATS        TransportType = "NATS"
	TransportTypeMQTT        TransportType = "MQTT"
)

// PresenceEvent is a transport-level liveness signal (online/offline)
// published for a peer. It is not tied to any particular session and is
// used by coordinators to pick reachable committees.
type PresenceEvent struct {
	PeerID         string         `json:"peer_id"`
	Status         PresenceStatus `json:"status"`
	Transport      TransportType  `json:"transport"`
	ConnectionID   string         `json:"connection_id,omitempty"`
	LastSeenUnixMs int64          `json:"last_seen_unix_ms"`
}

// RequestAccepted is the response envelope a participant returns to
// acknowledge an incoming request (e.g. a sign approval) and bind it to
// a SessionID with an expiry.
type RequestAccepted struct {
	Accepted  bool   `json:"accepted"`
	SessionID string `json:"session_id"`
	ExpiresAt string `json:"expires_at"`
}

// RequestRejected is the response envelope a participant returns to
// decline an incoming request, carrying a machine-readable ErrorCode and
// a human-readable ErrorMessage.
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
