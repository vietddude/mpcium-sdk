package protocol

import (
	"fmt"

	"google.golang.org/protobuf/proto"
)

func MarshalDeterministic(msg proto.Message) ([]byte, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(msg)
}

func ControlSigningBytes(msg *ControlMessage) ([]byte, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}
	cloned := proto.Clone(msg).(*ControlMessage)
	cloned.Signature = nil
	return MarshalDeterministic(cloned)
}

func PeerSigningBytes(msg *PeerMessage) ([]byte, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}
	cloned := proto.Clone(msg).(*PeerMessage)
	cloned.Signature = nil
	return MarshalDeterministic(cloned)
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
