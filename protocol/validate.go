package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

var (
	ErrNilMessage                  = errors.New("protocol: nil message")
	ErrMissingSessionID            = errors.New("protocol: missing session_id")
	ErrMissingParticipantID        = errors.New("protocol: missing participant_id")
	ErrMissingPartyKey             = errors.New("protocol: missing party_key")
	ErrDuplicateParticipantID      = errors.New("protocol: duplicate participant_id")
	ErrDuplicatePartyKey           = errors.New("protocol: duplicate party_key")
	ErrInvalidThreshold            = errors.New("protocol: invalid threshold")
	ErrInvalidPayload              = errors.New("protocol: invalid operation payload")
	ErrMissingSignature            = errors.New("protocol: missing signature")
	ErrInvalidRouting              = errors.New("protocol: invalid routing")
	ErrInvalidPhase                = errors.New("protocol: invalid phase")
	ErrInvalidControlMessageBody   = errors.New("protocol: invalid control message body")
	ErrInvalidPeerMessageBody      = errors.New("protocol: invalid peer message body")
	ErrParticipantNotInSession     = errors.New("protocol: participant not present in session")
	ErrUnsupportedDerivationOnOp   = errors.New("protocol: derivation is unsupported for operation")
	ErrUnsupportedDerivationOnAlgo = errors.New("protocol: derivation is unsupported for protocol")
)

func ValidateSessionStart(start *SessionStart) error {
	if start == nil {
		return ErrNilMessage
	}
	if start.GetSessionId() == "" {
		return ErrMissingSessionID
	}
	if start.GetProtocol() == ProtocolType_PROTOCOL_TYPE_UNSPECIFIED {
		return fmt.Errorf("%w: protocol", ErrInvalidPayload)
	}
	if start.GetOperation() == OperationType_OPERATION_TYPE_UNSPECIFIED {
		return fmt.Errorf("%w: operation", ErrInvalidPayload)
	}
	if len(start.GetParticipants()) == 0 {
		return fmt.Errorf("%w: participants", ErrInvalidPayload)
	}
	if int(start.GetThreshold()) < 1 || int(start.GetThreshold()) >= len(start.GetParticipants()) {
		return ErrInvalidThreshold
	}

	participantIDs := make(map[string]struct{}, len(start.GetParticipants()))
	partyKeys := make(map[string]struct{}, len(start.GetParticipants()))
	for _, participant := range start.GetParticipants() {
		if participant.GetParticipantId() == "" {
			return ErrMissingParticipantID
		}
		if len(participant.GetPartyKey()) == 0 {
			return fmt.Errorf("%w: %s", ErrMissingPartyKey, participant.GetParticipantId())
		}
		if _, ok := participantIDs[participant.GetParticipantId()]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicateParticipantID, participant.GetParticipantId())
		}
		key := string(participant.GetPartyKey())
		if _, ok := partyKeys[key]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicatePartyKey, participant.GetParticipantId())
		}
		participantIDs[participant.GetParticipantId()] = struct{}{}
		partyKeys[key] = struct{}{}
	}

	switch start.GetOperation() {
	case OperationType_OPERATION_TYPE_KEYGEN:
		keygen, ok := start.GetPayload().(*SessionStart_Keygen)
		if !ok || keygen.Keygen.GetKeyId() == "" {
			return fmt.Errorf("%w: keygen", ErrInvalidPayload)
		}
	case OperationType_OPERATION_TYPE_SIGN:
		sign, ok := start.GetPayload().(*SessionStart_Sign)
		if !ok || sign.Sign.GetKeyId() == "" || len(sign.Sign.GetSigningInput()) == 0 {
			return fmt.Errorf("%w: sign", ErrInvalidPayload)
		}
		if sign.Sign.GetDerivation() != nil && start.GetProtocol() == ProtocolType_PROTOCOL_TYPE_EDDSA {
			return ErrUnsupportedDerivationOnAlgo
		}
	case OperationType_OPERATION_TYPE_RESHARE:
		reshare, ok := start.GetPayload().(*SessionStart_Reshare)
		if !ok || reshare.Reshare.GetKeyId() == "" {
			return fmt.Errorf("%w: reshare", ErrInvalidPayload)
		}
		if len(reshare.Reshare.GetNewParticipants()) > 0 {
			if err := validateParticipants(reshare.Reshare.GetNewParticipants(), int(reshare.Reshare.GetNewThreshold())); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%w: operation", ErrInvalidPayload)
	}

	return nil
}

func ValidateControlMessage(msg *ControlMessage) error {
	if msg == nil {
		return ErrNilMessage
	}
	if msg.GetSessionId() == "" {
		return ErrMissingSessionID
	}
	if msg.GetCoordinatorId() == "" {
		return fmt.Errorf("%w: coordinator_id", ErrInvalidPayload)
	}
	if len(msg.GetSignature()) == 0 {
		return ErrMissingSignature
	}

	switch body := msg.GetBody().(type) {
	case *ControlMessage_SessionStart:
		if body.SessionStart == nil {
			return ErrInvalidControlMessageBody
		}
		if body.SessionStart.GetSessionId() != msg.GetSessionId() {
			return fmt.Errorf("%w: session_id mismatch", ErrInvalidControlMessageBody)
		}
		return ValidateSessionStart(body.SessionStart)
	case *ControlMessage_KeyExchangeBegin:
		if body.KeyExchangeBegin == nil {
			return ErrInvalidControlMessageBody
		}
	case *ControlMessage_MpcBegin:
		if body.MpcBegin == nil {
			return ErrInvalidControlMessageBody
		}
	case *ControlMessage_SessionAbort:
		if body.SessionAbort == nil {
			return ErrInvalidControlMessageBody
		}
	default:
		return ErrInvalidControlMessageBody
	}
	return nil
}

func ValidatePeerMessage(msg *PeerMessage) error {
	if msg == nil {
		return ErrNilMessage
	}
	if msg.GetSessionId() == "" {
		return ErrMissingSessionID
	}
	if msg.GetFromParticipantId() == "" {
		return fmt.Errorf("%w: from_participant_id", ErrInvalidRouting)
	}
	if msg.GetPhase() == ParticipantPhase_PARTICIPANT_PHASE_UNSPECIFIED {
		return ErrInvalidPhase
	}
	switch body := msg.GetBody().(type) {
	case *PeerMessage_KeyExchangeHello:
		if body.KeyExchangeHello == nil || len(body.KeyExchangeHello.GetX25519PublicKey()) == 0 {
			return ErrInvalidPeerMessageBody
		}
		if msg.GetBroadcast() || msg.GetToParticipantId() == "" {
			return fmt.Errorf("%w: key exchange hello must be direct", ErrInvalidRouting)
		}
		if len(msg.GetSignature()) == 0 {
			return ErrMissingSignature
		}
	case *PeerMessage_MpcPacket:
		if body.MpcPacket == nil || len(body.MpcPacket.GetPayload()) == 0 {
			return ErrInvalidPeerMessageBody
		}
		if msg.GetBroadcast() {
			if msg.GetToParticipantId() != "" {
				return fmt.Errorf("%w: broadcast message has recipient", ErrInvalidRouting)
			}
			if len(msg.GetSignature()) == 0 {
				return ErrMissingSignature
			}
			if len(body.MpcPacket.GetNonce()) != 0 {
				return fmt.Errorf("%w: broadcast packet must not include nonce", ErrInvalidRouting)
			}
		} else {
			if msg.GetToParticipantId() == "" {
				return fmt.Errorf("%w: direct packet missing recipient", ErrInvalidRouting)
			}
			if len(body.MpcPacket.GetNonce()) == 0 {
				return fmt.Errorf("%w: direct packet missing nonce", ErrInvalidRouting)
			}
		}
	default:
		return ErrInvalidPeerMessageBody
	}

	return nil
}

func CanonicalParticipants(participants []*SessionParticipant) []*SessionParticipant {
	cloned := slices.Clone(participants)
	slices.SortFunc(cloned, func(lhs, rhs *SessionParticipant) int {
		return bytes.Compare(lhs.GetPartyKey(), rhs.GetPartyKey())
	})
	return cloned
}

func FindParticipant(start *SessionStart, participantID string) (*SessionParticipant, error) {
	if err := ValidateSessionStart(start); err != nil {
		return nil, err
	}
	for _, participant := range start.GetParticipants() {
		if participant.GetParticipantId() == participantID {
			return participant, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrParticipantNotInSession, participantID)
}

func validateParticipants(participants []*SessionParticipant, threshold int) error {
	start := &SessionStart{
		SessionId:    "reshare",
		Protocol:     ProtocolType_PROTOCOL_TYPE_ECDSA,
		Operation:    OperationType_OPERATION_TYPE_KEYGEN,
		Threshold:    uint32(threshold),
		Participants: participants,
		Payload: &SessionStart_Keygen{
			Keygen: &KeygenPayload{KeyId: "reshare"},
		},
	}
	return ValidateSessionStart(start)
}
