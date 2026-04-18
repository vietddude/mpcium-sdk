# mpcium-sdk

Thin participant-side SDK on top of `tss-lib`, designed to run with an external coordinator/relay architecture.

Current supported runtime flow:

1. `SessionStart` is created by coordinator.
2. Coordinator sends `KeyExchangeBegin(exchange_id)`.
3. Participants exchange signed `key_exchange_hello` messages.
4. Coordinator sends `MPCBegin`.
5. SDK runs `keygen/sign` rounds via `tss-lib`.
6. Direct MPC packets are encrypted (E2E); broadcast packets are signed only.

## Features covered

- Protocols: `ECDSA`, `EdDSA`
- Operations: `KEYGEN`, `SIGN`
- Participant session API:
  - `Start()`
  - `HandleControl(*protocol.ControlMessage)`
  - `HandlePeer(*protocol.PeerMessage)`
  - `Status()`
- Security model:
  - Control + peer messages are signature-verified
  - Direct MPC packet: `encrypt + nonce + sign`
  - Broadcast MPC packet: `sign` only (no encryption, nonce must be empty)

## Package overview

- `participant`: main SDK runtime
- `protocol`: JSON contracts, validation, signing bytes
- `internal/wirecrypto`: direct packet key exchange/encryption helpers
- `identity`: identity lookup/signing interfaces
- `storage`: share/preparams/session artifact interfaces
- `mobilecore`: mobile runtime core with native transport/store adapters
- `mobile`: gomobile facade (JSON-first API)

## Minimal integration example

Below is a minimal coordinator-to-participant integration skeleton.

```go
package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/fystack/mpcium-sdk/participant"
	"github.com/fystack/mpcium-sdk/protocol"
)

// 1) Implement required interfaces:
// - identity.LocalIdentity
// - identity.PeerLookup
// - identity.CoordinatorLookup
// - storage.PreparamsStore / ShareStore / SessionArtifactsStore

func runSession(
	start *protocol.SessionStart,
	localID string,
	cfg participant.Config,
	sendPeer func(msgs []*protocol.PeerMessage) error,
	sendEvent func(events []*protocol.SessionEvent) error,
) error {
	sess, err := participant.New(cfg)
	if err != nil {
		return err
	}

	// Local start emits joined/ready events.
	effects, err := sess.Start()
	if err != nil {
		return err
	}
	if err := sendPeer(effects.PeerMessages); err != nil {
		return err
	}
	if err := sendEvent(effects.SessionEvents); err != nil {
		return err
	}

	// 2) Handle control from coordinator:
	//    a) KeyExchangeBegin (required)
	//    b) MPCBegin (only after key exchange done)
	handleControl := func(ctrl *protocol.ControlMessage) error {
		effects, err := sess.HandleControl(ctrl)
		if err != nil {
			return err
		}
		if err := sendPeer(effects.PeerMessages); err != nil {
			return err
		}
		if err := sendEvent(effects.SessionEvents); err != nil {
			return err
		}
		if effects.Result != nil {
			fmt.Printf("session result ready: %+v\n", effects.Result)
		}
		return nil
	}

	// 3) Handle peer messages routed by transport:
	handlePeer := func(peer *protocol.PeerMessage) error {
		effects, err := sess.HandlePeer(peer)
		if err != nil {
			return err
		}
		if err := sendPeer(effects.PeerMessages); err != nil {
			return err
		}
		if err := sendEvent(effects.SessionEvents); err != nil {
			return err
		}
		if effects.Result != nil {
			fmt.Printf("session result ready: %+v\n", effects.Result)
		}
		return nil
	}

	_ = handleControl
	_ = handlePeer
	return nil
}

// Coordinator signing reminder:
// - Build control payload using protocol.ControlSigningBytes(msg)
// - Sign bytes with coordinator private key (ed25519)
func signControl(priv ed25519.PrivateKey, msg *protocol.ControlMessage) error {
	payload, err := protocol.ControlSigningBytes(msg)
	if err != nil {
		return err
	}
	msg.Signature = ed25519.Sign(priv, payload)
	return nil
}
```

## Required control sequence

The participant runtime expects this sequence:

1. `SessionStart` (in config)
2. `KeyExchangeBegin{exchange_id}`
3. Exchange peer `KeyExchangeHello` until ready
4. `MPCBegin`

If `MPCBegin` arrives before key exchange is completed, the session fails with missing prerequisite.

## Preparams Slot Model

ECDSA keygen now requires a slot-based preparams store. The legacy single-cache model is removed.

- `PreparamsStore` must implement:
  - `LoadPreparamsSlot(protocol, slot)`
  - `SavePreparamsSlot(protocol, slot, blob)`
  - `LoadActivePreparamsSlot(protocol)`
  - `SaveActivePreparamsSlot(protocol, slot)`
- Runtime behavior:
  - Session resolves preparams with `pinned_slot -> active_slot` and fails fast on missing/invalid blobs.
  - Each session pins one slot in local `SessionArtifacts`, so in-flight sessions are deterministic across global rotates.
  - Successful ECDSA keygen writes new preparams to slot `next`, then rotates active pointer atomically and snapshots previous active into slot `prev`.
- Integrator requirements:
  - Seed at least one valid slot and set `active_slot` before running ECDSA keygen.
  - Update any existing preparams backend to the slot-aware API before upgrading SDK.

## Protocol rules to enforce in your transport

- Every `ControlMessage` and `PeerMessage` must carry a valid signature.
- For direct `PeerMessage` with `MPCPacket`:
  - `broadcast=false`
  - `to_participant_id` required
  - `nonce` required
- For broadcast `PeerMessage` with `MPCPacket`:
  - `broadcast=true`
  - `to_participant_id` must be empty
  - `nonce` must be empty

## Mobile facade (gomobile)

Public API:

- `NewClient(configJSON string) (*Client, error)`
- `Start() error`
- `Stop() error`
- `PollEvents(max int32) string`
- `ApproveSign(sessionID string, approved bool, reason string) error`
- `GetParticipantID() string`
- `GetIdentityPublicKeyBase64() string`

Adapter registration:

- `RegisterTransportAdapter(adapter TransportAdapter) error`
- `RegisterStoreAdapter(adapter StoreAdapter) error`

Runtime event types:

- `runtime_started`
- `presence_online`
- `sign_approval_required`
- `session_completed`
- `session_failed`
- `runtime_error`

## Notes

- `RESHARE` is not implemented yet.
- iOS runtime integration is out of scope for current v1.
