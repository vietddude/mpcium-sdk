package participant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	commonSig "github.com/bnb-chain/tss-lib/v2/common"
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	ecdsaSigning "github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	eddsaSigning "github.com/bnb-chain/tss-lib/v2/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/vietddude/mpcium-sdk/identity"
	"github.com/vietddude/mpcium-sdk/internal/wirecrypto"
	"github.com/vietddude/mpcium-sdk/protocol"
	"github.com/vietddude/mpcium-sdk/storage"
)

var (
	ErrInvalidControlSig    = errors.New("participant: invalid control message signature")
	ErrInvalidPeerSig       = errors.New("participant: invalid peer message signature")
	ErrReplayControl        = errors.New("participant: replayed control message sequence")
	ErrPartyNotRunning      = errors.New("participant: local tss party is not running")
	ErrUnsupportedOperation = errors.New("participant: operation is unsupported")
	ErrKeyExchangeRequired  = errors.New("participant: key exchange required before MPC begin")
	ErrKeyExchangeState     = errors.New("participant: invalid key exchange state")
	ErrPreparamsRequired    = errors.New("participant: preparams store is required for ecdsa keygen")
	ErrPreparamsSlotMissing = errors.New("participant: active preparams slot is missing")
	ErrPreparamsBlobMissing = errors.New("participant: preparams blob is missing")
)

const (
	PreparamsSlotNext = "next"
	PreparamsSlotPrev = "prev"
)

type Config struct {
	Start              *protocol.SessionStart
	LocalParticipantID string
	Identity           identity.LocalIdentity
	Peers              identity.PeerLookup
	Coordinator        identity.CoordinatorLookup
	Preparams          storage.PreparamsStore
	Shares             storage.ShareStore
	SessionArtifacts   storage.SessionArtifactsStore
}

type Result = protocol.Result

type CleanupHint struct {
	SessionID      string
	DropArtifacts  bool
	PersistOutcome bool
}

type Actions struct {
	PeerMessages  []*protocol.PeerMessage
	SessionEvents []*protocol.SessionEvent
	Result        *Result
	Cleanup       *CleanupHint
}

type Status struct {
	SessionID      string
	ParticipantID  string
	Phase          protocol.ParticipantPhase
	WaitingFor     []string
	FailureReason  protocol.FailureReason
	FailureDetails string
}

type ParticipantSession struct {
	cfg    Config
	status Status

	sortedParticipants []*protocol.SessionParticipant
	partyByID          map[string]*tss.PartyID

	party            tss.Party
	outCh            chan tss.Message
	ecdsaKeygenEndCh chan *ecdsaKeygen.LocalPartySaveData
	eddsaKeygenEndCh chan *eddsaKeygen.LocalPartySaveData
	ecdsaSignEndCh   chan *commonSig.SignatureData
	eddsaSignEndCh   chan *commonSig.SignatureData

	sequence       uint64
	controlSeqSeen uint64

	activeExchangeID string
	keyExchangeDone  bool
	kxLocalKey       *wirecrypto.KeyPair
	peerX25519Pub    map[string][]byte
	preparamsSlot    string
}

func New(cfg Config) (*ParticipantSession, error) {
	if cfg.Start == nil {
		return nil, errors.New("participant: missing session start")
	}
	if err := protocol.ValidateSessionStart(cfg.Start); err != nil {
		return nil, err
	}
	if cfg.LocalParticipantID == "" {
		return nil, errors.New("participant: missing local participant id")
	}
	if _, err := protocol.FindParticipant(cfg.Start, cfg.LocalParticipantID); err != nil {
		return nil, err
	}
	if cfg.Identity == nil {
		return nil, errors.New("participant: missing identity")
	}
	if cfg.Identity.ParticipantID() != cfg.LocalParticipantID {
		return nil, fmt.Errorf("participant: identity mismatch: %s != %s", cfg.Identity.ParticipantID(), cfg.LocalParticipantID)
	}
	if cfg.Peers == nil {
		return nil, errors.New("participant: missing peer lookup")
	}
	if cfg.Coordinator == nil {
		return nil, errors.New("participant: missing coordinator lookup")
	}

	sorted := protocol.CanonicalParticipants(cfg.Start.Participants)
	partyByID := make(map[string]*tss.PartyID, len(sorted))
	for _, participant := range sorted {
		key := partySortKey(participant)
		partyByID[participant.ParticipantID] = tss.NewPartyID(participant.ParticipantID, participant.ParticipantID, key)
	}

	session := &ParticipantSession{
		cfg: cfg,
		status: Status{
			SessionID:     cfg.Start.SessionID,
			ParticipantID: cfg.LocalParticipantID,
			Phase:         protocol.ParticipantPhaseCreated,
		},
		sortedParticipants: sorted,
		partyByID:          partyByID,
		peerX25519Pub:      make(map[string][]byte, len(sorted)),
	}
	if err := session.loadArtifacts(); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *ParticipantSession) Start() (Actions, error) {
	if s.status.Phase != protocol.ParticipantPhaseCreated {
		return Actions{}, nil
	}
	s.status.Phase = protocol.ParticipantPhaseJoining
	joined := s.newEvent()
	joined.PeerJoined = &protocol.PeerJoined{ParticipantID: s.cfg.LocalParticipantID}
	if err := s.signSessionEvent(joined); err != nil {
		return Actions{}, err
	}

	s.status.Phase = protocol.ParticipantPhaseReady
	ready := s.newEvent()
	ready.PeerReady = &protocol.PeerReady{ParticipantID: s.cfg.LocalParticipantID}
	if err := s.signSessionEvent(ready); err != nil {
		return Actions{}, err
	}

	if err := s.saveArtifacts(); err != nil {
		return Actions{}, err
	}
	return Actions{SessionEvents: []*protocol.SessionEvent{joined, ready}}, nil
}

func (s *ParticipantSession) HandleControl(msg *protocol.ControlMessage) (Actions, error) {
	if err := protocol.ValidateControlMessage(msg); err != nil {
		return Actions{}, err
	}
	if msg.SessionID != s.cfg.Start.SessionID {
		return Actions{}, fmt.Errorf("%w: %s", protocol.ErrMissingSessionID, msg.SessionID)
	}
	if err := s.verifyControlSignature(msg); err != nil {
		return Actions{}, err
	}
	if msg.Sequence <= s.controlSeqSeen {
		return Actions{}, ErrReplayControl
	}
	s.controlSeqSeen = msg.Sequence

	switch {
	case msg.SessionStart != nil:
		if msg.SessionStart.SessionID != s.cfg.Start.SessionID {
			return Actions{}, fmt.Errorf("%w: session mismatch", protocol.ErrInvalidControlMessageBody)
		}
		return Actions{}, nil
	case msg.KeyExchange != nil:
		actions, err := s.beginKeyExchange(msg.KeyExchange.ExchangeID)
		if err != nil {
			return s.fail(protocol.FailureReasonTSSError, err.Error()), err
		}
		if err := s.saveArtifacts(); err != nil {
			return Actions{}, err
		}
		return actions, nil
	case msg.MPCBegin != nil:
		if !s.keyExchangeDone || s.kxLocalKey == nil {
			err := ErrKeyExchangeRequired
			return s.fail(protocol.FailureReasonMissingPrerequisite, err.Error()), err
		}
		if err := s.startLocalParty(); err != nil {
			return s.fail(protocol.FailureReasonTSSError, err.Error()), err
		}
		actions, err := s.collectRuntimeActions()
		if err != nil {
			return s.fail(protocol.FailureReasonTSSError, err.Error()), err
		}
		if err := s.saveArtifacts(); err != nil {
			return Actions{}, err
		}
		return actions, nil
	default:
		return Actions{}, protocol.ErrInvalidControlMessageBody
	}
}

func (s *ParticipantSession) HandlePeer(msg *protocol.PeerMessage) (Actions, error) {
	if err := protocol.ValidatePeerMessage(msg); err != nil {
		return Actions{}, err
	}
	if msg.SessionID != s.cfg.Start.SessionID {
		return Actions{}, fmt.Errorf("%w: peer session mismatch", protocol.ErrMissingSessionID)
	}
	if msg.ToParticipantID != s.cfg.LocalParticipantID {
		return Actions{}, fmt.Errorf("%w: message not for local participant", protocol.ErrInvalidRouting)
	}
	if msg.FromParticipantID == s.cfg.LocalParticipantID {
		return Actions{}, fmt.Errorf("%w: self peer message", protocol.ErrInvalidRouting)
	}
	if err := s.verifyPeerSignature(msg); err != nil {
		return Actions{}, err
	}
	if msg.KeyExchangeHello != nil {
		actions, err := s.handleKeyExchangeHello(msg)
		if err != nil {
			return Actions{}, err
		}
		if err := s.saveArtifacts(); err != nil {
			return Actions{}, err
		}
		return actions, nil
	}

	if s.party == nil || !s.party.Running() {
		return Actions{}, ErrPartyNotRunning
	}

	from := s.partyByID[msg.FromParticipantID]
	if from == nil {
		return Actions{}, fmt.Errorf("%w: unknown peer %s", protocol.ErrInvalidRouting, msg.FromParticipantID)
	}
	if msg.MPCPacket == nil {
		return Actions{}, protocol.ErrInvalidPeerMessageBody
	}

	wirePayload, err := s.decryptDirectPacket(msg)
	if err != nil {
		return s.fail(protocol.FailureReasonDecryptFailed, err.Error()), err
	}
	if _, err := s.party.UpdateFromBytes(wirePayload, from, msg.Broadcast); err != nil {
		return s.fail(protocol.FailureReasonTSSError, err.Error()), fmt.Errorf("participant: update from bytes: %w", err)
	}

	actions, err := s.collectRuntimeActions()
	if err != nil {
		return s.fail(protocol.FailureReasonTSSError, err.Error()), err
	}
	if err := s.saveArtifacts(); err != nil {
		return Actions{}, err
	}
	return actions, nil
}

func (s *ParticipantSession) Tick(_ time.Time) (Actions, error) {
	if s.party == nil || !s.party.Running() {
		return Actions{}, nil
	}
	actions, err := s.collectRuntimeActions()
	if err != nil {
		return s.fail(protocol.FailureReasonTSSError, err.Error()), err
	}
	if err := s.saveArtifacts(); err != nil {
		return Actions{}, err
	}
	return actions, nil
}

func (s *ParticipantSession) Status() Status {
	status := s.status
	if s.party != nil && s.party.Running() {
		waiting := s.party.WaitingFor()
		status.WaitingFor = make([]string, 0, len(waiting))
		for _, partyID := range waiting {
			status.WaitingFor = append(status.WaitingFor, partyID.Id)
		}
		sort.Strings(status.WaitingFor)
	}
	return status
}

func (s *ParticipantSession) verifyControlSignature(msg *protocol.ControlMessage) error {
	publicKey, err := s.cfg.Coordinator.LookupCoordinator(msg.CoordinatorID)
	if err != nil {
		return err
	}
	payload, err := protocol.ControlSigningBytes(msg)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, msg.Signature) {
		return ErrInvalidControlSig
	}
	return nil
}

func (s *ParticipantSession) verifyPeerSignature(msg *protocol.PeerMessage) error {
	publicKey, err := s.cfg.Peers.LookupParticipant(msg.FromParticipantID)
	if err != nil {
		return err
	}
	payload, err := protocol.PeerSigningBytes(msg)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, msg.Signature) {
		return ErrInvalidPeerSig
	}
	return nil
}

func (s *ParticipantSession) beginKeyExchange(exchangeID string) (Actions, error) {
	if exchangeID == "" {
		return Actions{}, ErrKeyExchangeState
	}
	localKey, err := wirecrypto.GenerateKeyPair()
	if err != nil {
		return Actions{}, err
	}
	s.activeExchangeID = exchangeID
	s.keyExchangeDone = false
	s.kxLocalKey = localKey
	s.peerX25519Pub = make(map[string][]byte, len(s.sortedParticipants))
	s.status.Phase = protocol.ParticipantPhaseKeyExchange

	peerMessages := make([]*protocol.PeerMessage, 0, len(s.sortedParticipants)-1)
	for _, peerID := range s.otherParticipantIDs() {
		s.sequence++
		hello := &protocol.PeerMessage{
			SessionID:         s.cfg.Start.SessionID,
			Sequence:          s.sequence,
			FromParticipantID: s.cfg.LocalParticipantID,
			ToParticipantID:   peerID,
			Phase:             protocol.ParticipantPhaseKeyExchange,
			KeyExchangeHello: &protocol.KeyExchangeHello{
				ExchangeID:      exchangeID,
				X25519PublicKey: localKey.PublicKeyBytes(),
			},
		}
		if err := s.signPeerMessage(hello); err != nil {
			return Actions{}, err
		}
		peerMessages = append(peerMessages, hello)
	}
	return Actions{PeerMessages: peerMessages}, nil
}

func (s *ParticipantSession) handleKeyExchangeHello(msg *protocol.PeerMessage) (Actions, error) {
	if s.activeExchangeID == "" || s.kxLocalKey == nil {
		return Actions{}, ErrKeyExchangeState
	}
	if msg.KeyExchangeHello.ExchangeID != s.activeExchangeID {
		return Actions{}, fmt.Errorf("%w: exchange id mismatch", protocol.ErrInvalidPeerMessageBody)
	}
	s.peerX25519Pub[msg.FromParticipantID] = cloneBytes(msg.KeyExchangeHello.X25519PublicKey)
	if len(s.peerX25519Pub) < len(s.sortedParticipants)-1 {
		return Actions{}, nil
	}
	if s.keyExchangeDone {
		return Actions{}, nil
	}

	s.keyExchangeDone = true
	s.status.Phase = protocol.ParticipantPhaseKeyExchangeDone
	event := s.newEvent()
	event.PeerKeyExchangeDone = &protocol.PeerKeyExchangeDone{ParticipantID: s.cfg.LocalParticipantID}
	if err := s.signSessionEvent(event); err != nil {
		return Actions{}, err
	}
	return Actions{SessionEvents: []*protocol.SessionEvent{event}}, nil
}

func (s *ParticipantSession) decryptDirectPacket(msg *protocol.PeerMessage) ([]byte, error) {
	if s.kxLocalKey == nil {
		return nil, ErrKeyExchangeState
	}
	peerPub, ok := s.peerX25519Pub[msg.FromParticipantID]
	if !ok || len(peerPub) == 0 {
		return nil, fmt.Errorf("%w: missing peer key for %s", ErrKeyExchangeState, msg.FromParticipantID)
	}
	return wirecrypto.DecryptDirect(s.kxLocalKey, peerPub, msg, msg.MPCPacket.Nonce, msg.MPCPacket.Payload)
}

func (s *ParticipantSession) signPeerMessage(msg *protocol.PeerMessage) error {
	sigPayload, err := protocol.PeerSigningBytes(msg)
	if err != nil {
		return err
	}
	sig, err := s.cfg.Identity.Sign(sigPayload)
	if err != nil {
		return err
	}
	msg.Signature = sig
	return nil
}

func (s *ParticipantSession) signSessionEvent(msg *protocol.SessionEvent) error {
	sigPayload, err := protocol.SessionEventSigningBytes(msg)
	if err != nil {
		return err
	}
	sig, err := s.cfg.Identity.Sign(sigPayload)
	if err != nil {
		return err
	}
	msg.Signature = sig
	return nil
}

func (s *ParticipantSession) startLocalParty() error {
	if s.party != nil && s.party.Running() {
		return nil
	}
	curve, err := s.curve()
	if err != nil {
		return err
	}

	parties := make(tss.UnSortedPartyIDs, 0, len(s.sortedParticipants))
	for _, participant := range s.sortedParticipants {
		parties = append(parties, s.partyByID[participant.ParticipantID])
	}
	sortedParties := tss.SortPartyIDs(parties)
	ctx := tss.NewPeerContext(sortedParties)
	self := s.partyByID[s.cfg.LocalParticipantID]
	params := tss.NewParameters(curve, ctx, self, len(sortedParties), int(s.cfg.Start.Threshold))

	s.outCh = make(chan tss.Message, 256)

	switch s.cfg.Start.Operation {
	case protocol.OperationTypeKeygen:
		if s.cfg.Start.Protocol == protocol.ProtocolTypeECDSA {
			preparams, err := s.resolveECDSAPreparams()
			if err != nil {
				return err
			}
			s.ecdsaKeygenEndCh = make(chan *ecdsaKeygen.LocalPartySaveData, 1)
			s.party = ecdsaKeygen.NewLocalParty(params, s.outCh, s.ecdsaKeygenEndCh, *preparams)
		} else {
			s.eddsaKeygenEndCh = make(chan *eddsaKeygen.LocalPartySaveData, 1)
			s.party = eddsaKeygen.NewLocalParty(params, s.outCh, s.eddsaKeygenEndCh)
		}
	case protocol.OperationTypeSign:
		if s.cfg.Shares == nil {
			return errors.New("participant: missing share store")
		}
		keyID := s.cfg.Start.Sign.KeyID
		shareBlob, err := s.cfg.Shares.LoadShare(s.cfg.Start.Protocol, keyID)
		if err != nil {
			return err
		}
		if len(shareBlob) == 0 {
			return errors.New("participant: empty share blob")
		}
		if s.cfg.Start.Protocol == protocol.ProtocolTypeECDSA {
			keyData, err := decodeECDSAKeygenShare(shareBlob)
			if err != nil {
				return err
			}
			s.ecdsaSignEndCh = make(chan *commonSig.SignatureData, 1)
			signingInput := new(big.Int).SetBytes(s.cfg.Start.Sign.SigningInput)
			s.party = ecdsaSigning.NewLocalParty(signingInput, params, *keyData, s.outCh, s.ecdsaSignEndCh)
		} else {
			keyData, err := decodeEdDSAKeygenShare(shareBlob)
			if err != nil {
				return err
			}
			s.eddsaSignEndCh = make(chan *commonSig.SignatureData, 1)
			signingInput := new(big.Int).SetBytes(s.cfg.Start.Sign.SigningInput)
			s.party = eddsaSigning.NewLocalParty(signingInput, params, *keyData, s.outCh, s.eddsaSignEndCh)
		}
	default:
		return ErrUnsupportedOperation
	}
	if err := s.party.Start(); err != nil {
		return err
	}
	s.status.Phase = protocol.ParticipantPhaseMPCRunning
	return nil
}

func (s *ParticipantSession) curve() (elliptic.Curve, error) {
	switch s.cfg.Start.Protocol {
	case protocol.ProtocolTypeECDSA:
		return tss.S256(), nil
	case protocol.ProtocolTypeEdDSA:
		return tss.Edwards(), nil
	default:
		return nil, fmt.Errorf("participant: unsupported protocol %q", s.cfg.Start.Protocol)
	}
}

func (s *ParticipantSession) resolveECDSAPreparams() (*ecdsaKeygen.LocalPreParams, error) {
	if s.cfg.Preparams == nil {
		return nil, ErrPreparamsRequired
	}
	slot := s.preparamsSlot
	if slot == "" {
		activeSlot, err := s.cfg.Preparams.LoadActivePreparamsSlot(s.cfg.Start.Protocol)
		if err != nil {
			return nil, err
		}
		if activeSlot == "" {
			return nil, ErrPreparamsSlotMissing
		}
		slot = activeSlot
		s.preparamsSlot = activeSlot
		if err := s.saveArtifacts(); err != nil {
			return nil, err
		}
	}

	blob, err := s.cfg.Preparams.LoadPreparamsSlot(s.cfg.Start.Protocol, slot)
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return nil, ErrPreparamsBlobMissing
	}
	decoded, err := decodeECDSAPreparams(blob)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func (s *ParticipantSession) collectRuntimeActions() (Actions, error) {
	actions := Actions{}
	idle := 10 * time.Millisecond
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case msg := <-s.outCh:
			peerMessages, err := s.makePeerMessages(msg)
			if err != nil {
				return Actions{}, err
			}
			actions.PeerMessages = append(actions.PeerMessages, peerMessages...)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(1 * time.Millisecond)
		case <-timer.C:
			goto ENDS
		}
	}

ENDS:
	finalActions, err := s.collectTerminalResult()
	if err != nil {
		return Actions{}, err
	}
	actions.Result = finalActions.Result
	actions.Cleanup = finalActions.Cleanup
	actions.SessionEvents = append(actions.SessionEvents, finalActions.SessionEvents...)
	return actions, nil
}

func (s *ParticipantSession) collectTerminalResult() (Actions, error) {
	if s.ecdsaKeygenEndCh != nil {
		select {
		case data := <-s.ecdsaKeygenEndCh:
			return s.completeECDSAKeygen(data)
		default:
		}
	}
	if s.eddsaKeygenEndCh != nil {
		select {
		case data := <-s.eddsaKeygenEndCh:
			return s.completeEdDSAKeygen(data)
		default:
		}
	}
	if s.ecdsaSignEndCh != nil {
		select {
		case data := <-s.ecdsaSignEndCh:
			return s.completeSignature(data)
		default:
		}
	}
	if s.eddsaSignEndCh != nil {
		select {
		case data := <-s.eddsaSignEndCh:
			return s.completeSignature(data)
		default:
		}
	}
	return Actions{}, nil
}

func (s *ParticipantSession) completeECDSAKeygen(data *ecdsaKeygen.LocalPartySaveData) (Actions, error) {
	shareBlob, err := encodeECDSAKeygenShare(data)
	if err != nil {
		return Actions{}, err
	}
	if s.cfg.Shares == nil {
		return Actions{}, errors.New("participant: missing share store")
	}
	if err := s.cfg.Shares.SaveShare(s.cfg.Start.Protocol, s.cfg.Start.Keygen.KeyID, shareBlob); err != nil {
		return Actions{}, err
	}
	if s.cfg.Preparams == nil {
		return Actions{}, ErrPreparamsRequired
	}
	preparamsBlob, err := encodeECDSAPreparams(&data.LocalPreParams)
	if err != nil {
		return Actions{}, err
	}
	if err := s.cfg.Preparams.SavePreparamsSlot(s.cfg.Start.Protocol, PreparamsSlotNext, preparamsBlob); err != nil {
		return Actions{}, err
	}
	if err := RotatePreparamsSlot(s.cfg.Preparams, s.cfg.Start.Protocol, PreparamsSlotNext); err != nil {
		return Actions{}, err
	}

	result := &Result{KeyShare: &protocol.KeyShareResult{
		KeyID:     s.cfg.Start.Keygen.KeyID,
		ShareBlob: shareBlob,
		PublicKey: marshalECPoint(data.ECDSAPub),
	}}
	return s.complete(result), nil
}

func (s *ParticipantSession) completeEdDSAKeygen(data *eddsaKeygen.LocalPartySaveData) (Actions, error) {
	shareBlob, err := encodeEdDSAKeygenShare(data)
	if err != nil {
		return Actions{}, err
	}
	if s.cfg.Shares == nil {
		return Actions{}, errors.New("participant: missing share store")
	}
	if err := s.cfg.Shares.SaveShare(s.cfg.Start.Protocol, s.cfg.Start.Keygen.KeyID, shareBlob); err != nil {
		return Actions{}, err
	}

	result := &Result{KeyShare: &protocol.KeyShareResult{
		KeyID:     s.cfg.Start.Keygen.KeyID,
		ShareBlob: shareBlob,
		PublicKey: marshalECPoint(data.EDDSAPub),
	}}
	return s.complete(result), nil
}

func (s *ParticipantSession) completeSignature(sig *commonSig.SignatureData) (Actions, error) {
	if sig == nil {
		return Actions{}, errors.New("participant: nil signature data")
	}
	result := &Result{Signature: &protocol.SignatureResult{
		KeyID:             s.cfg.Start.Sign.KeyID,
		Signature:         cloneBytes(sig.GetSignature()),
		SignatureRecovery: cloneBytes(sig.GetSignatureRecovery()),
		R:                 cloneBytes(sig.GetR()),
		S:                 cloneBytes(sig.GetS()),
		SignedInput:       cloneBytes(sig.GetM()),
	}}
	return s.complete(result), nil
}

func (s *ParticipantSession) complete(result *Result) Actions {
	s.status.Phase = protocol.ParticipantPhaseCompleted
	s.resetKeyExchangeState()
	event := s.newEvent()
	event.SessionCompleted = &protocol.SessionCompleted{Result: result}
	if err := s.signSessionEvent(event); err != nil {
		return s.fail(protocol.FailureReasonTSSError, err.Error())
	}
	_ = s.dropArtifacts()
	return Actions{
		Result:        result,
		SessionEvents: []*protocol.SessionEvent{event},
		Cleanup:       &CleanupHint{SessionID: s.cfg.Start.SessionID, DropArtifacts: true, PersistOutcome: true},
	}
}

func (s *ParticipantSession) fail(reason protocol.FailureReason, details string) Actions {
	s.status.Phase = protocol.ParticipantPhaseFailed
	s.status.FailureReason = reason
	s.status.FailureDetails = details
	s.resetKeyExchangeState()
	event := s.newEvent()
	event.SessionFailed = &protocol.SessionFailed{Reason: reason, Detail: details}
	_ = s.signSessionEvent(event)
	_ = s.dropArtifacts()
	return Actions{
		SessionEvents: []*protocol.SessionEvent{event},
		Cleanup:       &CleanupHint{SessionID: s.cfg.Start.SessionID, DropArtifacts: true},
	}
}

func (s *ParticipantSession) newEvent() *protocol.SessionEvent {
	s.sequence++
	return &protocol.SessionEvent{
		SessionID:     s.cfg.Start.SessionID,
		ParticipantID: s.cfg.LocalParticipantID,
		Sequence:      s.sequence,
	}
}

func (s *ParticipantSession) makePeerMessages(message tss.Message) ([]*protocol.PeerMessage, error) {
	payload, routing, err := message.WireBytes()
	if err != nil {
		return nil, err
	}

	toPeerMessage := func(recipient string, broadcast bool) (*protocol.PeerMessage, error) {
		s.sequence++
		peer := &protocol.PeerMessage{
			SessionID:         s.cfg.Start.SessionID,
			Sequence:          s.sequence,
			FromParticipantID: s.cfg.LocalParticipantID,
			ToParticipantID:   recipient,
			Broadcast:         broadcast,
			Phase:             protocol.ParticipantPhaseMPCRunning,
			MPCPacket:         &protocol.MPCPacket{},
		}
		if !s.keyExchangeDone || s.kxLocalKey == nil {
			return nil, ErrKeyExchangeRequired
		}
		peerPub, ok := s.peerX25519Pub[recipient]
		if !ok || len(peerPub) == 0 {
			return nil, fmt.Errorf("%w: missing peer key for %s", ErrKeyExchangeState, recipient)
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
		return peer, nil
	}

	targets := make([]string, 0, len(routing.To))
	isBroadcast := routing.IsBroadcast || len(routing.To) == 0
	if routing.IsBroadcast || len(routing.To) == 0 {
		for _, peerID := range s.otherParticipantIDs() {
			targets = append(targets, peerID)
		}
	} else {
		for _, target := range routing.To {
			targets = append(targets, target.Id)
		}
	}

	messages := make([]*protocol.PeerMessage, 0, len(targets))
	for _, recipient := range targets {
		message, err := toPeerMessage(recipient, isBroadcast)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func (s *ParticipantSession) saveArtifacts() error {
	if s.cfg.SessionArtifacts == nil {
		return nil
	}
	blob, err := encodeStatusArtifact(
		s.status,
		s.controlSeqSeen,
		s.sequence,
		s.activeExchangeID,
		s.keyExchangeDone,
		s.peerX25519Pub,
		s.preparamsSlot,
	)
	if err != nil {
		return err
	}
	return s.cfg.SessionArtifacts.SaveSessionArtifacts(s.cfg.Start.SessionID, blob)
}

func (s *ParticipantSession) loadArtifacts() error {
	if s.cfg.SessionArtifacts == nil {
		return nil
	}
	blob, err := s.cfg.SessionArtifacts.LoadSessionArtifacts(s.cfg.Start.SessionID)
	if err != nil || len(blob) == 0 {
		return nil
	}
	status, controlSeq, sequence, activeExchangeID, keyExchangeDone, peerX25519, preparamsSlot, err := decodeStatusArtifact(blob)
	if err != nil {
		return err
	}
	if status.SessionID == s.cfg.Start.SessionID && status.ParticipantID == s.cfg.LocalParticipantID {
		s.status = status
		s.controlSeqSeen = controlSeq
		s.sequence = sequence
		s.activeExchangeID = activeExchangeID
		s.keyExchangeDone = keyExchangeDone
		s.peerX25519Pub = clonePeerKeyMap(peerX25519)
		s.preparamsSlot = preparamsSlot
		s.kxLocalKey = nil
		if s.activeExchangeID != "" && !s.keyExchangeDone {
			s.status.Phase = protocol.ParticipantPhaseKeyExchange
		}
	}
	return nil
}

func (s *ParticipantSession) dropArtifacts() error {
	if s.cfg.SessionArtifacts == nil {
		return nil
	}
	return s.cfg.SessionArtifacts.DeleteSessionArtifacts(s.cfg.Start.SessionID)
}

type statusArtifact struct {
	Version          int
	Status           Status
	ControlSeq       uint64
	Sequence         uint64
	ActiveExchangeID string
	KeyExchangeDone  bool
	PeerX25519Pub    map[string][]byte
	PreparamsSlot    string
}

func encodeStatusArtifact(
	status Status,
	controlSeq, sequence uint64,
	activeExchangeID string,
	keyExchangeDone bool,
	peerX25519 map[string][]byte,
	preparamsSlot string,
) ([]byte, error) {
	var buffer bytes.Buffer
	artifact := statusArtifact{
		Version:          2,
		Status:           status,
		ControlSeq:       controlSeq,
		Sequence:         sequence,
		ActiveExchangeID: activeExchangeID,
		KeyExchangeDone:  keyExchangeDone,
		PeerX25519Pub:    clonePeerKeyMap(peerX25519),
		PreparamsSlot:    preparamsSlot,
	}
	if err := gob.NewEncoder(&buffer).Encode(&artifact); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func decodeStatusArtifact(blob []byte) (Status, uint64, uint64, string, bool, map[string][]byte, string, error) {
	artifact := statusArtifact{}
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(&artifact); err != nil {
		return Status{}, 0, 0, "", false, nil, "", err
	}
	return artifact.Status, artifact.ControlSeq, artifact.Sequence, artifact.ActiveExchangeID, artifact.KeyExchangeDone, clonePeerKeyMap(artifact.PeerX25519Pub), artifact.PreparamsSlot, nil
}

func encodeECDSAKeygenShare(data *ecdsaKeygen.LocalPartySaveData) ([]byte, error) {
	return json.Marshal(data)
}

func decodeECDSAKeygenShare(blob []byte) (*ecdsaKeygen.LocalPartySaveData, error) {
	data := &ecdsaKeygen.LocalPartySaveData{}
	if err := json.Unmarshal(blob, data); err != nil {
		return nil, err
	}
	for _, point := range data.BigXj {
		if point != nil {
			point.SetCurve(tss.S256())
		}
	}
	if data.ECDSAPub != nil {
		data.ECDSAPub.SetCurve(tss.S256())
	}
	return data, nil
}

func encodeEdDSAKeygenShare(data *eddsaKeygen.LocalPartySaveData) ([]byte, error) {
	return json.Marshal(data)
}

func decodeEdDSAKeygenShare(blob []byte) (*eddsaKeygen.LocalPartySaveData, error) {
	data := &eddsaKeygen.LocalPartySaveData{}
	if err := json.Unmarshal(blob, data); err != nil {
		return nil, err
	}
	for _, point := range data.BigXj {
		if point != nil {
			point.SetCurve(tss.Edwards())
		}
	}
	if data.EDDSAPub != nil {
		data.EDDSAPub.SetCurve(tss.Edwards())
	}
	return data, nil
}

func encodeECDSAPreparams(data *ecdsaKeygen.LocalPreParams) ([]byte, error) {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(data); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func decodeECDSAPreparams(blob []byte) (*ecdsaKeygen.LocalPreParams, error) {
	data := &ecdsaKeygen.LocalPreParams{}
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(data); err != nil {
		return nil, err
	}
	return data, nil
}

type ecPoint interface {
	Curve() elliptic.Curve
	X() *big.Int
	Y() *big.Int
}

func marshalECPoint(point ecPoint) []byte {
	if point == nil {
		return nil
	}
	curve := point.Curve()
	if curve == nil {
		return nil
	}
	params := curve.Params()
	if params == nil {
		return nil
	}
	byteLen := (params.BitSize + 7) / 8
	publicKey := make([]byte, 1+2*byteLen)
	publicKey[0] = 4
	point.X().FillBytes(publicKey[1 : 1+byteLen])
	point.Y().FillBytes(publicKey[1+byteLen:])
	return publicKey
}

func cloneBytes(in []byte) []byte {
	return append([]byte(nil), in...)
}

func (s *ParticipantSession) otherParticipantIDs() []string {
	peerIDs := make([]string, 0, len(s.sortedParticipants)-1)
	for _, participant := range s.sortedParticipants {
		if participant.ParticipantID == s.cfg.LocalParticipantID {
			continue
		}
		peerIDs = append(peerIDs, participant.ParticipantID)
	}
	return peerIDs
}

func (s *ParticipantSession) resetKeyExchangeState() {
	s.activeExchangeID = ""
	s.keyExchangeDone = false
	s.kxLocalKey = nil
	s.peerX25519Pub = map[string][]byte{}
}

func clonePeerKeyMap(in map[string][]byte) map[string][]byte {
	if len(in) == 0 {
		return map[string][]byte{}
	}
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = cloneBytes(v)
	}
	return out
}

// partySortKey derives a stable big.Int key for tss.SortPartyIDs ordering.
// Using SHA-256 avoids ambiguity from variable-length integer encodings.
func partySortKey(participant *protocol.SessionParticipant) *big.Int {
	h := sha256.New()
	h.Write([]byte(participant.ParticipantID))
	h.Write([]byte{0})
	h.Write(participant.PartyKey)
	return new(big.Int).SetBytes(h.Sum(nil))
}
