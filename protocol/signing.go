package protocol

import (
	"fmt"
)

func ControlSigningBytes(msg *ControlMessage) ([]byte, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}
	cloned := *msg
	cloned.Signature = nil
	return MarshalJSON(&cloned)
}

func PeerSigningBytes(msg *PeerMessage) ([]byte, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}
	cloned := *msg
	cloned.Signature = nil
	return MarshalJSON(&cloned)
}

func MustControlSigningBytes(msg *ControlMessage) []byte {
	bytes, err := ControlSigningBytes(msg)
	if err != nil {
		panic(fmt.Sprintf("protocol: control signing bytes: %v", err))
	}
	return bytes
}

func MustPeerSigningBytes(msg *PeerMessage) []byte {
	bytes, err := PeerSigningBytes(msg)
	if err != nil {
		panic(fmt.Sprintf("protocol: peer signing bytes: %v", err))
	}
	return bytes
}
