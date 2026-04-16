package identity

import "crypto/ed25519"

type LocalIdentity interface {
	ParticipantID() string
	PublicKey() ed25519.PublicKey
	Sign(message []byte) ([]byte, error)
}

type PeerLookup interface {
	LookupParticipant(participantID string) (ed25519.PublicKey, error)
}

type CoordinatorLookup interface {
	LookupCoordinator(coordinatorID string) (ed25519.PublicKey, error)
}
