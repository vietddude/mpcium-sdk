// Package protocol's signing helpers produce the canonical byte payload
// that must be signed (and later verified) for each envelope type on the
// wire. The rule is the same for every envelope: clear Signature, then
// JSON-marshal the message. Signing and verifying must both go through
// these helpers so the bytes compared are identical on each side.

package protocol

import (
	"fmt"
)

// ControlSigningBytes returns the canonical payload to sign for a
// ControlMessage. Signature is cleared on a shallow copy so the input
// is not mutated and so signers/verifiers agree on the same bytes
// regardless of any Signature already present.
func ControlSigningBytes(msg *ControlMessage) ([]byte, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}
	cloned := *msg
	cloned.Signature = nil
	return MarshalJSON(&cloned)
}

// PeerSigningBytes returns the canonical payload to sign for a
// PeerMessage. For MPCPacket bodies, Payload/Nonce are already set to
// their final wire values (ciphertext+nonce for direct, plaintext for
// broadcast) before this call, so the signature covers exactly what the
// recipient will verify.
func PeerSigningBytes(msg *PeerMessage) ([]byte, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}
	cloned := *msg
	cloned.Signature = nil
	return MarshalJSON(&cloned)
}

// MustControlSigningBytes is a convenience wrapper around
// ControlSigningBytes that panics on error. Use only with inputs known
// to be non-nil (e.g. in tests or immediately after constructing the
// message).
func MustControlSigningBytes(msg *ControlMessage) []byte {
	bytes, err := ControlSigningBytes(msg)
	if err != nil {
		panic(fmt.Sprintf("protocol: control signing bytes: %v", err))
	}
	return bytes
}

// MustPeerSigningBytes is the panic-on-error variant of PeerSigningBytes.
// See MustControlSigningBytes for usage caveats.
func MustPeerSigningBytes(msg *PeerMessage) []byte {
	bytes, err := PeerSigningBytes(msg)
	if err != nil {
		panic(fmt.Sprintf("protocol: peer signing bytes: %v", err))
	}
	return bytes
}

// SessionEventSigningBytes returns the canonical payload to sign for a
// SessionEvent emitted by a participant.
func SessionEventSigningBytes(msg *SessionEvent) ([]byte, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}
	cloned := *msg
	cloned.Signature = nil
	return MarshalJSON(&cloned)
}

// MustSessionEventSigningBytes is the panic-on-error variant of
// SessionEventSigningBytes. See MustControlSigningBytes for usage caveats.
func MustSessionEventSigningBytes(msg *SessionEvent) []byte {
	bytes, err := SessionEventSigningBytes(msg)
	if err != nil {
		panic(fmt.Sprintf("protocol: session event signing bytes: %v", err))
	}
	return bytes
}
