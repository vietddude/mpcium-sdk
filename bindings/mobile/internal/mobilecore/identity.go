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

type coordinatorLookup struct {
	keys map[string]ed25519.PublicKey
}

func newCoordinatorLookup(coordinatorID string, publicKey []byte) (*coordinatorLookup, error) {
	if coordinatorID == "" {
		return nil, fmt.Errorf("coordinator_id is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid coordinator public key size")
	}
	return &coordinatorLookup{
		keys: map[string]ed25519.PublicKey{
			coordinatorID: append([]byte(nil), publicKey...),
		},
	}, nil
}

func (l *coordinatorLookup) LookupCoordinator(coordinatorID string) (ed25519.PublicKey, error) {
	key, ok := l.keys[coordinatorID]
	if !ok {
		return nil, fmt.Errorf("coordinator %s not found", coordinatorID)
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
