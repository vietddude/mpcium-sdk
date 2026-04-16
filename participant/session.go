package participant

import (
	"errors"
	"fmt"
	"time"

	"github.com/vietddude/mpcium-sdk/identity"
	"github.com/vietddude/mpcium-sdk/protocol"
	"github.com/vietddude/mpcium-sdk/storage"
)

var ErrNotImplemented = errors.New("participant: not implemented")

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

type Effects struct {
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

	return &ParticipantSession{
		cfg: cfg,
		status: Status{
			SessionID:     cfg.Start.GetSessionId(),
			ParticipantID: cfg.LocalParticipantID,
			Phase:         protocol.ParticipantPhase_PARTICIPANT_PHASE_CREATED,
		},
	}, nil
}

func (s *ParticipantSession) Start() (Effects, error) {
	return Effects{}, ErrNotImplemented
}

func (s *ParticipantSession) HandleControl(msg *protocol.ControlMessage) (Effects, error) {
	if err := protocol.ValidateControlMessage(msg); err != nil {
		return Effects{}, err
	}
	return Effects{}, ErrNotImplemented
}

func (s *ParticipantSession) HandlePeer(msg *protocol.PeerMessage) (Effects, error) {
	if err := protocol.ValidatePeerMessage(msg); err != nil {
		return Effects{}, err
	}
	return Effects{}, ErrNotImplemented
}

func (s *ParticipantSession) Tick(_ time.Time) (Effects, error) {
	return Effects{}, nil
}

func (s *ParticipantSession) Status() Status {
	return s.status
}
