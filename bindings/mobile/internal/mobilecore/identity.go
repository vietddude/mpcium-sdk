package mobilecore

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

type localIdentity struct {
	participantID string
	publicKey     ed25519.PublicKey
	privateKey    ed25519.PrivateKey
}

func newLocalIdentity(participantID string, privateKey []byte) (*localIdentity, error) {
	if participantID == "" {
		return nil, fmt.Errorf("participant id is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size")
	}
	priv := ed25519.PrivateKey(append([]byte(nil), privateKey...))
	pub := priv.Public().(ed25519.PublicKey)
	return &localIdentity{
		participantID: participantID,
		publicKey:     append([]byte(nil), pub...),
		privateKey:    priv,
	}, nil
}

func (i *localIdentity) ParticipantID() string {
	return i.participantID
}

func (i *localIdentity) PublicKey() ed25519.PublicKey {
	return append([]byte(nil), i.publicKey...)
}

func (i *localIdentity) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(i.privateKey, message), nil
}

type peerLookup struct {
	keys map[string]ed25519.PublicKey
}

func newPeerLookup(keys map[string]ed25519.PublicKey) *peerLookup {
	cloned := make(map[string]ed25519.PublicKey, len(keys))
	for participantID, key := range keys {
		cloned[participantID] = append([]byte(nil), key...)
	}
	return &peerLookup{keys: cloned}
}

func (l *peerLookup) LookupParticipant(participantID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[participantID]
	if !ok {
		return nil, fmt.Errorf("participant %s not found", participantID)
	}
	return append([]byte(nil), key...), nil
}

type OrchestratorLookup struct {
	keys map[string]ed25519.PublicKey
}

func newOrchestratorLookup(orchestratorID string, publicKey []byte) (*OrchestratorLookup, error) {
	if orchestratorID == "" {
		return nil, fmt.Errorf("orchestrator_id is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid orchestrator public key size")
	}
	return &OrchestratorLookup{
		keys: map[string]ed25519.PublicKey{
			orchestratorID: append([]byte(nil), publicKey...),
		},
	}, nil
}

func (l *OrchestratorLookup) LookupOrchestrator(orchestratorID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[orchestratorID]
	if !ok {
		return nil, fmt.Errorf("orchestrator %s not found", orchestratorID)
	}
	return append([]byte(nil), key...), nil
}

func generateIdentityPrivateKey() ([]byte, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), privateKey...), nil
}
