package mobilecore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/fystack/mpcium-sdk/participant"
	"github.com/fystack/mpcium-sdk/protocol"
)

const bootstrapPreparamsSlot = "bootstrap"

type Runtime struct {
	cfg         Config
	relay       Relay
	stores      Stores
	identity    *localIdentity
	coordLookup *coordinatorLookup

	sessionsMu  sync.RWMutex
	sessions    map[string]*participant.ParticipantSession
	sessionMeta map[string]string

	seqMu       sync.Mutex
	sessionSeq  map[string]uint64
	pendingMu   sync.Mutex
	pendingSign map[string]pendingApproval
	subs        []Subscription
	events      eventQueue
}

type pendingApproval struct {
	msg        *protocol.ControlMessage
	receivedAt time.Time
}

type PendingApprovalArtifact struct {
	SessionID        string                   `json:"session_id"`
	ReceivedAtUnixMs int64                    `json:"received_at_unix_ms"`
	ControlMessage   *protocol.ControlMessage `json:"control_message"`
}

func NewRuntime(cfg Config, relay Relay, stores Stores) (*Runtime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if relay == nil {
		return nil, fmt.Errorf("relay is required")
	}
	if stores == nil {
		return nil, fmt.Errorf("stores are required")
	}
	identityKey, err := resolveIdentityKey(cfg, stores)
	if err != nil {
		relay.Close()
		_ = stores.Close()
		return nil, err
	}
	identity, err := newLocalIdentity(cfg.NodeID, identityKey)
	if err != nil {
		relay.Close()
		_ = stores.Close()
		return nil, err
	}
	coordinatorPub, err := cfg.CoordinatorPublicKeyBytes()
	if err != nil {
		relay.Close()
		_ = stores.Close()
		return nil, err
	}
	coordLookup, err := newCoordinatorLookup(cfg.CoordinatorID, coordinatorPub)
	if err != nil {
		relay.Close()
		_ = stores.Close()
		return nil, err
	}
	return &Runtime{
		cfg:         cfg,
		relay:       relay,
		stores:      stores,
		identity:    identity,
		coordLookup: coordLookup,
		sessions:    map[string]*participant.ParticipantSession{},
		sessionMeta: map[string]string{},
		sessionSeq:  map[string]uint64{},
		pendingSign: map[string]pendingApproval{},
	}, nil
}

func resolveIdentityKey(cfg Config, stores Stores) ([]byte, error) {
	if fromConfig, err := cfg.IdentityPrivateKeyBytes(); err != nil {
		return nil, err
	} else if len(fromConfig) > 0 {
		if len(fromConfig) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("identity private key has invalid size")
		}
		if err := stores.SaveIdentityPrivateKey(fromConfig); err != nil {
			return nil, err
		}
		return fromConfig, nil
	}

	if existing, err := stores.LoadIdentityPrivateKey(); err != nil {
		return nil, err
	} else if len(existing) > 0 {
		if len(existing) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("stored identity private key has invalid size")
		}
		return existing, nil
	}

	generated, err := generateIdentityPrivateKey()
	if err != nil {
		return nil, err
	}
	if err := stores.SaveIdentityPrivateKey(generated); err != nil {
		return nil, err
	}
	return generated, nil
}

func (r *Runtime) Close() error {
	for _, sub := range r.subs {
		_ = sub.Unsubscribe()
	}
	if r.relay != nil {
		r.relay.Close()
	}
	if r.stores != nil {
		return r.stores.Close()
	}
	return nil
}

func (r *Runtime) ParticipantID() string {
	return r.identity.ParticipantID()
}

func (r *Runtime) IdentityPublicKey() []byte {
	return r.identity.PublicKey()
}

func (r *Runtime) PollEvents(max int) []RuntimeEvent {
	return r.events.popN(max)
}

func (r *Runtime) Run(ctx context.Context) error {
	r.events.push(newRuntimeEvent("runtime_started", "", "", "mobile runtime started"))
	if err := r.ensureECDSAPreparams(); err != nil {
		return err
	}
	if err := r.restorePendingApprovals(); err != nil {
		return err
	}
	r.expirePendingApprovals()
	if err := r.subscribe(); err != nil {
		return err
	}
	if err := r.publishPresence(protocol.PresenceStatusOnline); err != nil {
		return err
	}

	tick := time.NewTicker(r.cfg.TickInterval)
	defer tick.Stop()
	presenceTick := time.NewTicker(r.cfg.PresenceInterval)
	defer presenceTick.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = r.publishPresence(protocol.PresenceStatusOffline)
			return nil
		case <-tick.C:
			if err := r.relay.Poll(); err != nil {
				r.events.push(newRuntimeEvent("runtime_error", "", "", err.Error()))
			}
			if err := r.tickSessions(); err != nil {
				r.events.push(newRuntimeEvent("runtime_error", "", "", err.Error()))
			}
			r.expirePendingApprovals()
		case <-presenceTick.C:
			if err := r.publishPresence(protocol.PresenceStatusOnline); err != nil {
				r.events.push(newRuntimeEvent("runtime_error", "", "", err.Error()))
			}
		}
	}
}

func (r *Runtime) ApproveSign(sessionID string, approved bool, reason string) error {
	r.pendingMu.Lock()
	pending, ok := r.pendingSign[sessionID]
	if ok {
		delete(r.pendingSign, sessionID)
	}
	r.pendingMu.Unlock()
	if !ok {
		return fmt.Errorf("session %s has no pending sign approval", sessionID)
	}
	if err := r.stores.DeletePendingSignApproval(sessionID); err != nil {
		return err
	}
	if !approved {
		detail := reason
		if detail == "" {
			detail = "sign request rejected by user"
		}
		return r.publishUserRejectedSessionFailed(sessionID, detail)
	}
	if err := r.startSession(pending.msg); err != nil {
		return err
	}
	return nil
}

func (r *Runtime) ensureECDSAPreparams() error {
	r.events.push(newRuntimeEvent("preparams_check_started", "", "ECDSA", "checking ecdsa preparams"))
	activeSlot, err := r.stores.LoadActivePreparamsSlot(protocol.ProtocolTypeECDSA)
	if err != nil {
		return fmt.Errorf("load active ecdsa preparams slot: %w", err)
	}
	if activeSlot != "" {
		existing, err := r.stores.LoadPreparamsSlot(protocol.ProtocolTypeECDSA, activeSlot)
		if err != nil {
			return fmt.Errorf("load ecdsa preparams slot %q: %w", activeSlot, err)
		}
		if len(existing) > 0 {
			r.events.push(newRuntimeEvent("preparams_ready", "", "ECDSA", "using cached ecdsa preparams slot "+activeSlot))
			return nil
		}
		r.events.push(newRuntimeEvent("preparams_cache_miss", "", "ECDSA", "active ecdsa preparams slot "+activeSlot+" is empty"))
	}
	r.events.push(newRuntimeEvent("preparams_generation_started", "", "ECDSA", "generating ecdsa preparams"))
	preparams, err := ecdsaKeygen.GeneratePreParams(5 * time.Minute)
	if err != nil {
		return fmt.Errorf("generate ecdsa preparams: %w", err)
	}
	r.events.push(newRuntimeEvent("preparams_generation_completed", "", "ECDSA", "generated ecdsa preparams"))
	blob, err := encodeECDSAPreparams(preparams)
	if err != nil {
		return fmt.Errorf("encode ecdsa preparams: %w", err)
	}
	if err := r.stores.SavePreparamsSlot(protocol.ProtocolTypeECDSA, bootstrapPreparamsSlot, blob); err != nil {
		return fmt.Errorf("save ecdsa preparams slot: %w", err)
	}
	if err := r.stores.SaveActivePreparamsSlot(protocol.ProtocolTypeECDSA, bootstrapPreparamsSlot); err != nil {
		return fmt.Errorf("save active ecdsa preparams slot: %w", err)
	}
	r.events.push(newRuntimeEvent("preparams_ready", "", "ECDSA", "saved ecdsa preparams slot "+bootstrapPreparamsSlot))
	return nil
}

func encodeECDSAPreparams(data *ecdsaKeygen.LocalPreParams) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *Runtime) subscribe() error {
	controlSub, err := r.relay.Subscribe(controlSubject(r.cfg.NodeID), func(raw []byte) {
		if err := r.handleControl(raw); err != nil {
			r.events.push(newRuntimeEvent("runtime_error", "", "", err.Error()))
		}
	})
	if err != nil {
		return err
	}
	r.subs = append(r.subs, controlSub)

	p2pSub, err := r.relay.Subscribe(p2pWildcardSubject(r.cfg.NodeID), func(raw []byte) {
		if err := r.handlePeer(raw); err != nil {
			r.events.push(newRuntimeEvent("runtime_error", "", "", err.Error()))
		}
	})
	if err != nil {
		return err
	}
	r.subs = append(r.subs, p2pSub)
	return r.relay.Flush()
}

func (r *Runtime) handleControl(raw []byte) error {
	var msg protocol.ControlMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return err
	}
	if err := protocol.ValidateControlMessage(&msg); err != nil {
		return err
	}
	if msg.SessionStart != nil {
		if msg.SessionStart.Operation == protocol.OperationTypeSign {
			if err := r.verifyControlSignature(&msg); err != nil {
				return err
			}
			if err := r.savePendingApproval(&msg); err != nil {
				return err
			}
			r.pendingMu.Lock()
			r.pendingSign[msg.SessionID] = pendingApproval{msg: &msg, receivedAt: time.Now()}
			r.pendingMu.Unlock()
			r.events.push(newRuntimeEvent("sign_approval_required", msg.SessionID, "SIGN", "user confirmation is required"))
			return nil
		}
		return r.startSession(&msg)
	}
	session := r.getSession(msg.SessionID)
	if session == nil {
		return nil
	}
	if msg.SessionAbort != nil {
		r.dropSession(msg.SessionID)
		r.events.push(newRuntimeEvent("session_failed", msg.SessionID, r.getSessionOperation(msg.SessionID), msg.SessionAbort.Detail))
		_ = r.stores.DeleteSessionArtifacts(msg.SessionID)
		return nil
	}
	actions, err := session.HandleControl(&msg)
	if err != nil {
		return err
	}
	return r.dispatchActions(actions)
}

func (r *Runtime) startSession(msg *protocol.ControlMessage) error {
	if msg == nil || msg.SessionStart == nil {
		return errors.New("session start message is required")
	}
	if err := r.verifyControlSignature(msg); err != nil {
		return err
	}
	r.sessionsMu.RLock()
	activeSessions := len(r.sessions)
	r.sessionsMu.RUnlock()
	if activeSessions >= r.cfg.MaxActiveSessions {
		return errors.New("max active sessions reached")
	}
	peerKeys := make(map[string]ed25519.PublicKey, len(msg.SessionStart.Participants))
	for _, participantDef := range msg.SessionStart.Participants {
		if participantDef.ParticipantID == r.cfg.NodeID {
			continue
		}
		peerKeys[participantDef.ParticipantID] = append([]byte(nil), participantDef.IdentityPublicKey...)
	}
	sess, err := participant.New(participant.Config{
		Start:              msg.SessionStart,
		LocalParticipantID: r.cfg.NodeID,
		Identity:           r.identity,
		Peers:              newPeerLookup(peerKeys),
		Coordinator:        r.coordLookup,
		Preparams:          r.stores,
		Shares:             r.stores,
		SessionArtifacts:   r.stores,
	})
	if err != nil {
		return err
	}
	r.sessionsMu.Lock()
	r.sessions[msg.SessionID] = sess
	r.sessionMeta[msg.SessionID] = string(msg.SessionStart.Operation)
	r.sessionsMu.Unlock()

	actions, err := sess.Start()
	if err != nil {
		return err
	}
	return r.dispatchActions(actions)
}

func (r *Runtime) handlePeer(raw []byte) error {
	var msg protocol.PeerMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return err
	}
	session := r.getSession(msg.SessionID)
	if session == nil {
		return nil
	}
	actions, err := session.HandlePeer(&msg)
	if err != nil {
		return err
	}
	return r.dispatchActions(actions)
}

func (r *Runtime) tickSessions() error {
	r.sessionsMu.RLock()
	ids := make([]string, 0, len(r.sessions))
	for sessionID := range r.sessions {
		ids = append(ids, sessionID)
	}
	r.sessionsMu.RUnlock()

	for _, sessionID := range ids {
		session := r.getSession(sessionID)
		if session == nil {
			continue
		}
		actions, err := session.Tick(time.Now())
		if err != nil {
			return err
		}
		if err := r.dispatchActions(actions); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) dispatchActions(actions participant.Actions) error {
	for _, peerMsg := range actions.PeerMessages {
		raw, err := json.Marshal(peerMsg)
		if err != nil {
			return err
		}
		if err := r.relay.Publish(p2pSubject(peerMsg.ToParticipantID, peerMsg.SessionID), raw); err != nil {
			return err
		}
	}
	for _, sessionEvent := range actions.SessionEvents {
		raw, err := json.Marshal(sessionEvent)
		if err != nil {
			return err
		}
		if err := r.relay.Publish(sessionEventSubject(sessionEvent.SessionID), raw); err != nil {
			return err
		}
		if sessionEvent.SessionCompleted != nil {
			r.events.push(newRuntimeEvent("session_completed", sessionEvent.SessionID, r.getSessionOperation(sessionEvent.SessionID), "session completed"))
			r.dropSession(sessionEvent.SessionID)
		}
		if sessionEvent.SessionFailed != nil {
			r.events.push(newRuntimeEvent("session_failed", sessionEvent.SessionID, r.getSessionOperation(sessionEvent.SessionID), sessionEvent.SessionFailed.Detail))
			r.dropSession(sessionEvent.SessionID)
		}
	}
	return nil
}

func (r *Runtime) verifyControlSignature(msg *protocol.ControlMessage) error {
	publicKey, err := r.coordLookup.LookupCoordinator(msg.CoordinatorID)
	if err != nil {
		return err
	}
	payload, err := protocol.ControlSigningBytes(msg)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, msg.Signature) {
		return participant.ErrInvalidControlSig
	}
	return nil
}

func (r *Runtime) publishPresence(status protocol.PresenceStatus) error {
	transportType := r.relay.ProtocolType()
	if transportType == protocol.TransportTypeUnspecified {
		return errors.New("transport type is required")
	}
	event := protocol.PresenceEvent{
		PeerID:         r.cfg.NodeID,
		Status:         status,
		Transport:      transportType,
		LastSeenUnixMs: time.Now().UnixMilli(),
	}
	if status == protocol.PresenceStatusOnline {
		event.ConnectionID = r.relay.ConnectionID()
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := r.relay.Publish(presenceSubject(r.cfg.NodeID), raw); err != nil {
		return err
	}
	if status == protocol.PresenceStatusOnline {
		r.events.push(newRuntimeEvent("presence_online", "", "", "presence published"))
	}
	return nil
}

func (r *Runtime) expirePendingApprovals() {
	now := time.Now()
	type expiredItem struct {
		sessionID string
	}
	expired := make([]expiredItem, 0)
	r.pendingMu.Lock()
	for sessionID, item := range r.pendingSign {
		if now.Sub(item.receivedAt) >= r.cfg.ApprovalTimeout {
			expired = append(expired, expiredItem{sessionID: sessionID})
			delete(r.pendingSign, sessionID)
		}
	}
	r.pendingMu.Unlock()

	for _, item := range expired {
		_ = r.stores.DeletePendingSignApproval(item.sessionID)
		_ = r.publishSessionFailed(item.sessionID, protocol.FailureReasonTimeout, "sign approval timed out")
		r.events.push(newRuntimeEvent("session_failed", item.sessionID, "SIGN", "sign approval timed out"))
	}
}

func (r *Runtime) publishUserRejectedSessionFailed(sessionID, detail string) error {
	if err := r.publishSessionFailed(sessionID, protocol.FailureReasonAborted, detail); err != nil {
		return err
	}
	r.events.push(newRuntimeEvent("session_failed", sessionID, "SIGN", detail))
	return nil
}

func (r *Runtime) publishSessionFailed(sessionID string, reason protocol.FailureReason, detail string) error {
	event := &protocol.SessionEvent{
		SessionID:     sessionID,
		ParticipantID: r.cfg.NodeID,
		Sequence:      r.nextSessionSequence(sessionID),
		SessionFailed: &protocol.SessionFailed{
			Reason: reason,
			Detail: detail,
		},
	}
	payload, err := protocol.SessionEventSigningBytes(event)
	if err != nil {
		return err
	}
	event.Signature = ed25519.Sign(r.identity.privateKey, payload)
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return r.relay.Publish(sessionEventSubject(sessionID), raw)
}

func (r *Runtime) nextSessionSequence(sessionID string) uint64 {
	r.seqMu.Lock()
	defer r.seqMu.Unlock()
	r.sessionSeq[sessionID]++
	return r.sessionSeq[sessionID]
}

func (r *Runtime) getSession(sessionID string) *participant.ParticipantSession {
	r.sessionsMu.RLock()
	defer r.sessionsMu.RUnlock()
	return r.sessions[sessionID]
}

func (r *Runtime) dropSession(sessionID string) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()
	delete(r.sessions, sessionID)
	delete(r.sessionMeta, sessionID)
}

func (r *Runtime) getSessionOperation(sessionID string) string {
	r.sessionsMu.RLock()
	defer r.sessionsMu.RUnlock()
	return r.sessionMeta[sessionID]
}

func (r *Runtime) savePendingApproval(msg *protocol.ControlMessage) error {
	if msg == nil || msg.SessionID == "" {
		return fmt.Errorf("pending approval message is required")
	}
	artifact := PendingApprovalArtifact{
		SessionID:        msg.SessionID,
		ReceivedAtUnixMs: time.Now().UnixMilli(),
		ControlMessage:   msg,
	}
	blob, err := json.Marshal(artifact)
	if err != nil {
		return err
	}
	return r.stores.SavePendingSignApproval(msg.SessionID, blob)
}

func (r *Runtime) restorePendingApprovals() error {
	blobs, err := r.stores.ListPendingSignApprovals()
	if err != nil {
		return err
	}
	if len(blobs) == 0 {
		return nil
	}
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	for sessionID, blob := range blobs {
		var artifact PendingApprovalArtifact
		if err := json.Unmarshal(blob, &artifact); err != nil || artifact.ControlMessage == nil {
			_ = r.stores.DeletePendingSignApproval(sessionID)
			continue
		}
		receivedAt := time.UnixMilli(artifact.ReceivedAtUnixMs)
		if artifact.ReceivedAtUnixMs == 0 {
			receivedAt = time.Now()
		}
		r.pendingSign[sessionID] = pendingApproval{
			msg:        artifact.ControlMessage,
			receivedAt: receivedAt,
		}
		r.events.push(newRuntimeEvent("sign_approval_required", sessionID, "SIGN", "user confirmation is required"))
	}
	return nil
}
