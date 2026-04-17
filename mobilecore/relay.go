package mobilecore

import "github.com/vietddude/mpcium-sdk/protocol"

type Subscription interface {
	Unsubscribe() error
}

type Relay interface {
	Subscribe(subject string, handler func([]byte)) (Subscription, error)
	Publish(subject string, payload []byte) error
	Flush() error
	Poll() error
	Close()
	ConnectionID() string
	ProtocolType() protocol.TransportType
}
