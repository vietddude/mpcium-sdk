package storage

import "github.com/vietddude/mpcium-sdk/protocol"

type PreparamsStore interface {
	LoadPreparams(protocol protocol.ProtocolType, keyID string) ([]byte, error)
}

type ShareStore interface {
	LoadShare(protocol protocol.ProtocolType, keyID string) ([]byte, error)
	SaveShare(protocol protocol.ProtocolType, keyID string, share []byte) error
}

type SessionArtifactsStore interface {
	LoadSessionArtifacts(sessionID string) ([]byte, error)
	SaveSessionArtifacts(sessionID string, artifact []byte) error
	DeleteSessionArtifacts(sessionID string) error
}
