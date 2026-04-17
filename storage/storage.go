package storage

import "github.com/vietddude/mpcium-sdk/protocol"

type PreparamsStore interface {
	LoadPreparamsSlot(protocol protocol.ProtocolType, slot string) ([]byte, error)
	SavePreparamsSlot(protocol protocol.ProtocolType, slot string, preparams []byte) error
	LoadActivePreparamsSlot(protocol protocol.ProtocolType) (string, error)
	SaveActivePreparamsSlot(protocol protocol.ProtocolType, slot string) error
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
