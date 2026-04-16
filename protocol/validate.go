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
	if start.SessionID == "" {
		return ErrMissingSessionID
	}
	if start.Protocol == ProtocolTypeUnspecified {
		return fmt.Errorf("%w: protocol", ErrInvalidPayload)
	}
	if start.Operation == OperationTypeUnspecified {
		return fmt.Errorf("%w: operation", ErrInvalidPayload)
	}
	if len(start.Participants) == 0 {
		return fmt.Errorf("%w: participants", ErrInvalidPayload)
	}
	if int(start.Threshold) < 1 || int(start.Threshold) >= len(start.Participants) {
		return ErrInvalidThreshold
	}

	participantIDs := make(map[string]struct{}, len(start.Participants))
	partyKeys := make(map[string]struct{}, len(start.Participants))
	for _, participant := range start.Participants {
		if participant.ParticipantID == "" {
			return ErrMissingParticipantID
		}
		if len(participant.PartyKey) == 0 {
			return fmt.Errorf("%w: %s", ErrMissingPartyKey, participant.ParticipantID)
		}
		if _, ok := participantIDs[participant.ParticipantID]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicateParticipantID, participant.ParticipantID)
		}
		key := string(participant.PartyKey)
		if _, ok := partyKeys[key]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicatePartyKey, participant.ParticipantID)
		}
		participantIDs[participant.ParticipantID] = struct{}{}
		partyKeys[key] = struct{}{}
	}

	switch start.Operation {
	case OperationTypeKeygen:
		if start.Keygen == nil || start.Keygen.KeyID == "" {
			return fmt.Errorf("%w: keygen", ErrInvalidPayload)
		}
		if start.Sign != nil || start.Reshare != nil {
			return fmt.Errorf("%w: keygen body collision", ErrInvalidPayload)
		}
	case OperationTypeSign:
		if start.Sign == nil || start.Sign.KeyID == "" || len(start.Sign.SigningInput) == 0 {
			return fmt.Errorf("%w: sign", ErrInvalidPayload)
		}
		if start.Sign.Derivation != nil && start.Protocol == ProtocolTypeEdDSA {
			return ErrUnsupportedDerivationOnAlgo
		}
		if start.Keygen != nil || start.Reshare != nil {
			return fmt.Errorf("%w: sign body collision", ErrInvalidPayload)
		}
	case OperationTypeReshare:
		if start.Reshare == nil || start.Reshare.KeyID == "" {
			return fmt.Errorf("%w: reshare", ErrInvalidPayload)
		}
		if len(start.Reshare.NewParticipants) > 0 {
			if err := validateParticipants(start.Reshare.NewParticipants, int(start.Reshare.NewThreshold)); err != nil {
				return err
			}
		}
		if start.Keygen != nil || start.Sign != nil {
			return fmt.Errorf("%w: reshare body collision", ErrInvalidPayload)
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
	if msg.SessionID == "" {
		return ErrMissingSessionID
	}
	if msg.CoordinatorID == "" {
		return fmt.Errorf("%w: coordinator_id", ErrInvalidPayload)
	}
	if len(msg.Signature) == 0 {
		return ErrMissingSignature
	}

	bodyCount := 0
	if msg.SessionStart != nil {
		bodyCount++
		if msg.SessionStart.SessionID != msg.SessionID {
			return fmt.Errorf("%w: session_id mismatch", ErrInvalidControlMessageBody)
		}
		if err := ValidateSessionStart(msg.SessionStart); err != nil {
			return err
		}
	}
	if msg.KeyExchange != nil {
		bodyCount++
		if msg.KeyExchange.ExchangeID == "" {
			return ErrInvalidControlMessageBody
		}
	}
	if msg.MPCBegin != nil {
		bodyCount++
	}
	if msg.SessionAbort != nil {
		bodyCount++
	}
	if bodyCount != 1 {
		return ErrInvalidControlMessageBody
	}
	return nil
}

func ValidatePeerMessage(msg *PeerMessage) error {
	if msg == nil {
		return ErrNilMessage
	}
	if msg.SessionID == "" {
		return ErrMissingSessionID
	}
	if msg.FromParticipantID == "" {
		return fmt.Errorf("%w: from_participant_id", ErrInvalidRouting)
	}
	if msg.Phase == ParticipantPhaseUnspecified {
		return ErrInvalidPhase
	}
	if len(msg.Signature) == 0 {
		return ErrMissingSignature
	}

	bodyCount := 0
	if msg.KeyExchangeHello != nil {
		bodyCount++
		if msg.KeyExchangeHello.ExchangeID == "" {
			return ErrInvalidPeerMessageBody
		}
		if len(msg.KeyExchangeHello.X25519PublicKey) == 0 {
			return ErrInvalidPeerMessageBody
		}
		if msg.Broadcast || msg.ToParticipantID == "" {
			return fmt.Errorf("%w: key exchange hello must be direct", ErrInvalidRouting)
		}
	}
	if msg.MPCPacket != nil {
		bodyCount++
		if len(msg.MPCPacket.Payload) == 0 {
			return ErrInvalidPeerMessageBody
		}
		if msg.Broadcast {
			if msg.ToParticipantID != "" {
				return fmt.Errorf("%w: broadcast message has recipient", ErrInvalidRouting)
			}
			if len(msg.MPCPacket.Nonce) != 0 {
				return fmt.Errorf("%w: broadcast packet must not include nonce", ErrInvalidRouting)
			}
		} else if msg.ToParticipantID == "" {
			return fmt.Errorf("%w: direct packet missing recipient", ErrInvalidRouting)
		} else if len(msg.MPCPacket.Nonce) == 0 {
			return fmt.Errorf("%w: direct packet missing nonce", ErrInvalidRouting)
		}
	}
	if bodyCount != 1 {
		return ErrInvalidPeerMessageBody
	}
	return nil
}

func CanonicalParticipants(participants []*SessionParticipant) []*SessionParticipant {
	cloned := slices.Clone(participants)
	slices.SortFunc(cloned, func(lhs, rhs *SessionParticipant) int {
		return bytes.Compare(lhs.PartyKey, rhs.PartyKey)
	})
	return cloned
}

func FindParticipant(start *SessionStart, participantID string) (*SessionParticipant, error) {
	if err := ValidateSessionStart(start); err != nil {
		return nil, err
	}
	for _, participant := range start.Participants {
		if participant.ParticipantID == participantID {
			return participant, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrParticipantNotInSession, participantID)
}

func validateParticipants(participants []*SessionParticipant, threshold int) error {
	start := &SessionStart{
		SessionID:    "reshare",
		Protocol:     ProtocolTypeECDSA,
		Operation:    OperationTypeKeygen,
		Threshold:    uint32(threshold),
		Participants: participants,
		Keygen:       &KeygenPayload{KeyID: "reshare"},
	}
	return ValidateSessionStart(start)
}
