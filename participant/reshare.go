package participant

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	ecdsaResharing "github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	eddsaResharing "github.com/bnb-chain/tss-lib/v2/eddsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium-sdk/internal/wirecrypto"
	"github.com/fystack/mpcium-sdk/protocol"
	"github.com/fystack/mpcium-sdk/storage"
)

func (s *ParticipantSession) startReshareParties() error {
	if s.status.Phase == protocol.ParticipantPhaseResharePrepared || s.reshareCommitted {
		return nil
	}
	if s.cfg.ShareRotations == nil {
		return ErrShareRotationRequired
	}
	curve, err := s.curve()
	if err != nil {
		return err
	}

	oldParties := sortedPartyIDs(s.partyByRole[protocol.CommitteeRoleOld])
	newParties := sortedPartyIDs(s.partyByRole[protocol.CommitteeRoleNew])
	oldContext := tss.NewPeerContext(oldParties)
	newContext := tss.NewPeerContext(newParties)
	s.outCh = make(chan tss.Message, 512)

	for _, role := range []protocol.CommitteeRole{protocol.CommitteeRoleNew, protocol.CommitteeRoleOld} {
		self := s.partyByRole[role][s.cfg.LocalParticipantID]
		if self == nil {
			continue
		}
		params := tss.NewReSharingParameters(
			curve,
			oldContext,
			newContext,
			self,
			len(oldParties),
			int(s.cfg.Start.Threshold),
			len(newParties),
			int(s.cfg.Start.Reshare.NewThreshold),
		)
		party, err := s.newReshareParty(role, params, len(newParties))
		if err != nil {
			return err
		}
		s.reshareParties[role] = party
	}

	// New parties must be listening before old parties emit round one.
	for _, role := range []protocol.CommitteeRole{protocol.CommitteeRoleNew, protocol.CommitteeRoleOld} {
		party := s.reshareParties[role]
		if party == nil {
			continue
		}
		if err := party.Start(); err != nil {
			return err
		}
	}
	s.status.Phase = protocol.ParticipantPhaseMPCRunning
	return nil
}

func (s *ParticipantSession) newReshareParty(role protocol.CommitteeRole, params *tss.ReSharingParameters, newPartyCount int) (tss.Party, error) {
	keyID := s.cfg.Start.Reshare.KeyID
	switch s.cfg.Start.Protocol {
	case protocol.ProtocolTypeECDSA:
		var input ecdsaKeygen.LocalPartySaveData
		if role == protocol.CommitteeRoleOld {
			blob, err := s.loadActiveShare(keyID)
			if err != nil {
				return nil, err
			}
			decoded, err := decodeECDSAKeygenShare(blob)
			if err != nil {
				return nil, err
			}
			input = *decoded
			s.reshareOldPublicKey = marshalECPoint(decoded.ECDSAPub)
		} else {
			input = ecdsaKeygen.NewLocalPartySaveData(newPartyCount)
			preparams, err := s.resolveECDSAPreparams()
			if err != nil {
				return nil, err
			}
			input.LocalPreParams = *preparams
		}
		endCh := make(chan *ecdsaKeygen.LocalPartySaveData, 1)
		s.ecdsaReshareEndCh[role] = endCh
		return ecdsaResharing.NewLocalParty(params, input, s.outCh, endCh), nil
	case protocol.ProtocolTypeEdDSA:
		var input eddsaKeygen.LocalPartySaveData
		if role == protocol.CommitteeRoleOld {
			blob, err := s.loadActiveShare(keyID)
			if err != nil {
				return nil, err
			}
			decoded, err := decodeEdDSAKeygenShare(blob)
			if err != nil {
				return nil, err
			}
			input = *decoded
			s.reshareOldPublicKey = marshalEd25519PublicKey(decoded.EDDSAPub)
		} else {
			input = eddsaKeygen.NewLocalPartySaveData(newPartyCount)
		}
		endCh := make(chan *eddsaKeygen.LocalPartySaveData, 1)
		s.eddsaReshareEndCh[role] = endCh
		return eddsaResharing.NewLocalParty(params, input, s.outCh, endCh), nil
	default:
		return nil, fmt.Errorf("participant: unsupported protocol %q", s.cfg.Start.Protocol)
	}
}

func (s *ParticipantSession) loadActiveShare(keyID string) ([]byte, error) {
	if s.cfg.Shares == nil {
		return nil, errors.New("participant: missing share store")
	}
	blob, err := s.cfg.Shares.LoadShare(s.cfg.Start.Protocol, keyID)
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return nil, errors.New("participant: empty share blob")
	}
	return blob, nil
}

func (s *ParticipantSession) collectReshareTerminalResult() (Actions, error) {
	for role, endCh := range s.ecdsaReshareEndCh {
		if s.reshareRoleDone[role] {
			continue
		}
		select {
		case data := <-endCh:
			s.reshareRoleDone[role] = true
			if role == protocol.CommitteeRoleNew {
				var err error
				s.reshareReplacement, err = encodeECDSAKeygenShare(data)
				if err != nil {
					return Actions{}, err
				}
				s.reshareNewPublicKey = marshalECPoint(data.ECDSAPub)
			}
		default:
		}
	}
	for role, endCh := range s.eddsaReshareEndCh {
		if s.reshareRoleDone[role] {
			continue
		}
		select {
		case data := <-endCh:
			s.reshareRoleDone[role] = true
			if role == protocol.CommitteeRoleNew {
				var err error
				s.reshareReplacement, err = encodeEdDSAKeygenShare(data)
				if err != nil {
					return Actions{}, err
				}
				s.reshareNewPublicKey = marshalEd25519PublicKey(data.EDDSAPub)
			}
		default:
		}
	}
	if !s.allLocalReshareRolesDone() {
		return Actions{}, nil
	}

	if len(s.reshareReplacement) == 0 && s.partyByRole[protocol.CommitteeRoleNew][s.cfg.LocalParticipantID] != nil {
		return Actions{}, errors.New("participant: reshare replacement output missing")
	}
	publicKey := cloneBytes(s.reshareNewPublicKey)
	if len(publicKey) == 0 {
		publicKey = cloneBytes(s.reshareOldPublicKey)
	}
	if len(s.reshareOldPublicKey) > 0 && !bytes.Equal(publicKey, s.reshareOldPublicKey) {
		return Actions{}, errors.New("participant: reshare public key changed")
	}

	rotation := storage.ShareRotation{Replacement: cloneBytes(s.reshareReplacement)}
	if s.partyByRole[protocol.CommitteeRoleNew][s.cfg.LocalParticipantID] == nil {
		rotation = storage.ShareRotation{Retire: true}
	}
	if err := rotation.Validate(); err != nil {
		return Actions{}, err
	}
	if err := s.cfg.ShareRotations.StageShareRotation(s.cfg.Start.Protocol, s.cfg.Start.Reshare.KeyID, s.cfg.Start.SessionID, rotation); err != nil {
		return Actions{}, err
	}

	result := &protocol.ReshareResult{
		KeyID:        s.cfg.Start.Reshare.KeyID,
		PublicKey:    cloneBytes(publicKey),
		NewThreshold: s.cfg.Start.Reshare.NewThreshold,
	}
	s.preparedReshare = cloneReshareResult(result)
	s.status.Phase = protocol.ParticipantPhaseResharePrepared
	s.resetKeyExchangeState()
	event := s.newEvent()
	event.ResharePrepared = &protocol.ResharePrepared{Result: cloneReshareResult(result)}
	if err := s.signSessionEvent(event); err != nil {
		_ = s.cfg.ShareRotations.AbortShareRotation(s.cfg.Start.Protocol, s.cfg.Start.Reshare.KeyID, s.cfg.Start.SessionID)
		s.preparedReshare = nil
		return Actions{}, err
	}
	if err := s.saveCheckpoint(); err != nil {
		_ = s.cfg.ShareRotations.AbortShareRotation(s.cfg.Start.Protocol, s.cfg.Start.Reshare.KeyID, s.cfg.Start.SessionID)
		s.preparedReshare = nil
		return Actions{}, err
	}
	return Actions{SessionEvents: []*protocol.SessionEvent{event}}, nil
}

func (s *ParticipantSession) commitReshare() (Actions, error) {
	if s.cfg.Start.Operation != protocol.OperationTypeReshare {
		return Actions{}, protocol.ErrInvalidControlMessageBody
	}
	if s.reshareCommitted && s.status.Phase == protocol.ParticipantPhaseCompleted {
		if err := s.cfg.ShareRotations.CommitShareRotation(s.cfg.Start.Protocol, s.cfg.Start.Reshare.KeyID, s.cfg.Start.SessionID); err != nil {
			return Actions{}, err
		}
		return s.complete(&Result{Reshare: cloneReshareResult(s.preparedReshare)}), nil
	}
	if s.status.Phase != protocol.ParticipantPhaseResharePrepared || s.preparedReshare == nil {
		return Actions{}, ErrReshareCommitPhase
	}
	if err := s.cfg.ShareRotations.CommitShareRotation(s.cfg.Start.Protocol, s.cfg.Start.Reshare.KeyID, s.cfg.Start.SessionID); err != nil {
		return Actions{}, err
	}
	s.reshareCommitted = true
	if err := s.saveCheckpoint(); err != nil {
		return Actions{}, err
	}
	result := &Result{Reshare: cloneReshareResult(s.preparedReshare)}
	return s.complete(result), nil
}

func (s *ParticipantSession) abort(abort *protocol.SessionAbort) (Actions, error) {
	if abort == nil {
		return Actions{}, protocol.ErrInvalidControlMessageBody
	}
	if s.cfg.Start.Operation == protocol.OperationTypeReshare {
		if s.reshareCommitted {
			return Actions{}, nil
		}
		if err := s.cfg.ShareRotations.AbortShareRotation(s.cfg.Start.Protocol, s.cfg.Start.Reshare.KeyID, s.cfg.Start.SessionID); err != nil {
			return Actions{}, err
		}
	}
	s.status.Phase = protocol.ParticipantPhaseAborted
	s.status.FailureReason = abort.Reason
	s.status.FailureDetails = abort.Detail
	s.resetKeyExchangeState()
	event := s.newEvent()
	event.SessionFailed = &protocol.SessionFailed{Reason: abort.Reason, Detail: abort.Detail}
	if err := s.signSessionEvent(event); err != nil {
		return Actions{}, err
	}
	_ = s.saveCheckpoint()
	return Actions{
		SessionEvents: []*protocol.SessionEvent{event},
		Cleanup:       &CleanupHint{SessionID: s.cfg.Start.SessionID, DropCheckpoint: true},
	}, nil
}

func (s *ParticipantSession) makeResharePeerMessages(message tss.Message) ([]*protocol.PeerMessage, error) {
	payload, routing, err := message.WireBytes()
	if err != nil {
		return nil, err
	}
	fromRole, ok := s.committeeRoleForParty(routing.From)
	if !ok {
		return nil, fmt.Errorf("%w: unknown source tss party", protocol.ErrInvalidRouting)
	}
	targets, err := s.reshareTargets(routing)
	if err != nil {
		return nil, err
	}

	messages := make([]*protocol.PeerMessage, 0, len(targets))
	for _, target := range targets {
		if target.party.KeyInt().Cmp(routing.From.KeyInt()) == 0 {
			continue
		}
		if target.party.Id == s.cfg.LocalParticipantID {
			party := s.reshareParties[target.role]
			if party == nil {
				return nil, fmt.Errorf("%w: local committee role %s", protocol.ErrInvalidRouting, target.role)
			}
			from := s.partyByRole[fromRole][routing.From.Id]
			if _, err := party.UpdateFromBytes(payload, from, routing.IsBroadcast); err != nil {
				return nil, fmt.Errorf("participant: local reshare route: %w", err)
			}
			continue
		}

		s.sequence++
		peer := &protocol.PeerMessage{
			SessionID:         s.cfg.Start.SessionID,
			Sequence:          s.sequence,
			FromParticipantID: routing.From.Id,
			ToParticipantID:   target.party.Id,
			Broadcast:         routing.IsBroadcast,
			Phase:             protocol.ParticipantPhaseMPCRunning,
			MPCPacket: &protocol.MPCPacket{
				FromCommittee: fromRole,
				ToCommittee:   target.role,
			},
		}
		if !s.keyExchangeDone || s.kxLocalKey == nil {
			return nil, ErrKeyExchangeRequired
		}
		peerPub := s.peerX25519Pub[target.party.Id]
		if len(peerPub) == 0 {
			return nil, fmt.Errorf("%w: missing peer key for %s", ErrKeyExchangeState, target.party.Id)
		}
		nonce, ciphertext, err := wirecrypto.EncryptDirect(s.kxLocalKey, peerPub, peer, payload)
		if err != nil {
			return nil, err
		}
		peer.MPCPacket.Nonce = nonce
		peer.MPCPacket.Payload = ciphertext
		if err := s.signPeerMessage(peer); err != nil {
			return nil, err
		}
		messages = append(messages, peer)
	}
	return messages, nil
}

type reshareTarget struct {
	role  protocol.CommitteeRole
	party *tss.PartyID
}

func (s *ParticipantSession) reshareTargets(routing *tss.MessageRouting) ([]reshareTarget, error) {
	if routing == nil {
		return nil, protocol.ErrInvalidRouting
	}
	targets := make([]reshareTarget, 0, len(routing.To))
	seen := make(map[string]struct{}, len(routing.To))
	for _, partyID := range routing.To {
		role, ok := s.committeeRoleForParty(partyID)
		if !ok {
			return nil, fmt.Errorf("%w: unknown target tss party", protocol.ErrInvalidRouting)
		}
		key := string(role) + ":" + partyID.KeyInt().String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, reshareTarget{role: role, party: partyID})
	}
	return targets, nil
}

func (s *ParticipantSession) committeeRoleForParty(partyID *tss.PartyID) (protocol.CommitteeRole, bool) {
	if partyID == nil {
		return protocol.CommitteeRoleUnspecified, false
	}
	for _, role := range []protocol.CommitteeRole{protocol.CommitteeRoleOld, protocol.CommitteeRoleNew} {
		for _, candidate := range s.partyByRole[role] {
			if candidate.KeyInt().Cmp(partyID.KeyInt()) == 0 {
				return role, true
			}
		}
	}
	return protocol.CommitteeRoleUnspecified, false
}

func (s *ParticipantSession) allLocalReshareRolesDone() bool {
	if len(s.reshareParties) == 0 {
		return false
	}
	for role := range s.reshareParties {
		if !s.reshareRoleDone[role] {
			return false
		}
	}
	return true
}

func (s *ParticipantSession) anyPartyRunning() bool {
	if s.party != nil && s.party.Running() {
		return true
	}
	for _, party := range s.reshareParties {
		if party != nil && party.Running() {
			return true
		}
	}
	return false
}

func buildPartyIDs(participants []*protocol.SessionParticipant) map[string]*tss.PartyID {
	byID := make(map[string]*tss.PartyID, len(participants))
	unsorted := make(tss.UnSortedPartyIDs, 0, len(participants))
	for _, participant := range participants {
		partyID := tss.NewPartyID(participant.ParticipantID, participant.ParticipantID, partySortKey(participant))
		byID[participant.ParticipantID] = partyID
		unsorted = append(unsorted, partyID)
	}
	_ = tss.SortPartyIDs(unsorted)
	return byID
}

func sortedPartyIDs(byID map[string]*tss.PartyID) tss.SortedPartyIDs {
	unsorted := make(tss.UnSortedPartyIDs, 0, len(byID))
	for _, partyID := range byID {
		unsorted = append(unsorted, partyID)
	}
	return tss.SortPartyIDs(unsorted)
}

func unionParticipants(oldParticipants, newParticipants []*protocol.SessionParticipant) []*protocol.SessionParticipant {
	byID := make(map[string]*protocol.SessionParticipant, len(oldParticipants)+len(newParticipants))
	for _, participant := range oldParticipants {
		byID[participant.ParticipantID] = participant
	}
	for _, participant := range newParticipants {
		if _, ok := byID[participant.ParticipantID]; !ok {
			byID[participant.ParticipantID] = participant
		}
	}
	ids := make([]string, 0, len(byID))
	for participantID := range byID {
		ids = append(ids, participantID)
	}
	sort.Strings(ids)
	participants := make([]*protocol.SessionParticipant, 0, len(ids))
	for _, participantID := range ids {
		participants = append(participants, byID[participantID])
	}
	return participants
}

func committeeRoleIsSet(role protocol.CommitteeRole) bool {
	return role == protocol.CommitteeRoleOld || role == protocol.CommitteeRoleNew
}

func cloneReshareResult(result *protocol.ReshareResult) *protocol.ReshareResult {
	if result == nil {
		return nil
	}
	cloned := *result
	cloned.PublicKey = cloneBytes(result.PublicKey)
	return &cloned
}
