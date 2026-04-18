package wirecrypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/fystack/mpcium-sdk/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	x25519KeySize = 32
	nonceSize     = chacha20poly1305.NonceSize
)

var (
	ErrInvalidPublicKey = errors.New("wirecrypto: invalid x25519 public key")
	ErrInvalidSignature = errors.New("wirecrypto: invalid ed25519 signature")
)

type KeyPair struct {
	private *ecdh.PrivateKey
}

func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{private: privateKey}, nil
}

func RestoreKeyPair(privateKey []byte) (*KeyPair, error) {
	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &KeyPair{private: key}, nil
}

func (k *KeyPair) PrivateKeyBytes() []byte {
	return append([]byte(nil), k.private.Bytes()...)
}

func (k *KeyPair) PublicKeyBytes() []byte {
	return append([]byte(nil), k.private.PublicKey().Bytes()...)
}

func BuildAAD(msg *protocol.PeerMessage) ([]byte, error) {
	if msg == nil {
		return nil, protocol.ErrNilMessage
	}
	cloned := *msg
	cloned.Signature = nil
	if cloned.MPCPacket != nil {
		packet := *cloned.MPCPacket
		packet.Payload = nil
		packet.Nonce = nil
		cloned.MPCPacket = &packet
	}
	return protocol.MarshalJSON(&cloned)
}

func Verify(publicKey ed25519.PublicKey, message, signature []byte) error {
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func EncryptDirect(local *KeyPair, peerPublic []byte, message *protocol.PeerMessage, plaintext []byte) ([]byte, []byte, error) {
	peer, err := ecdh.X25519().NewPublicKey(peerPublic)
	if err != nil {
		return nil, nil, ErrInvalidPublicKey
	}
	aad, err := BuildAAD(message)
	if err != nil {
		return nil, nil, err
	}
	key, err := derivePacketKey(local.private, peer, message.SessionID, message.FromParticipantID, message.ToParticipantID)
	if err != nil {
		return nil, nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func DecryptDirect(local *KeyPair, peerPublic []byte, message *protocol.PeerMessage, nonce, ciphertext []byte) ([]byte, error) {
	peer, err := ecdh.X25519().NewPublicKey(peerPublic)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	aad, err := BuildAAD(message)
	if err != nil {
		return nil, err
	}
	key, err := derivePacketKey(local.private, peer, message.SessionID, message.FromParticipantID, message.ToParticipantID)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func derivePacketKey(private *ecdh.PrivateKey, public *ecdh.PublicKey, sessionID, fromParticipantID, toParticipantID string) ([]byte, error) {
	sharedSecret, err := private.ECDH(public)
	if err != nil {
		return nil, err
	}
	info := fmt.Sprintf("mpcium-sdk/direct-v1:%s:%s:%s", sessionID, fromParticipantID, toParticipantID)
	return hkdf.Key(sha256.New, sharedSecret, nil, info, x25519KeySize)
}
