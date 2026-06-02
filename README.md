# mpcium-sdk

Thin participant-side SDK on top of `tss-lib`, designed to run with an external Orchestrator/relay architecture.

Current supported runtime flow:

1. `SessionStart` is created by Orchestrator.
2. Orchestrator sends `KeyExchangeBegin(exchange_id)`.
3. Participants exchange signed `key_exchange_hello` messages.
4. Orchestrator sends `MPCBegin`.
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
- `api/gateway/v1`: external cosigner gateway gRPC stream contract
- `internal/wirecrypto`: direct packet key exchange/encryption helpers
- `identity`: identity lookup/signing interfaces
- `storage`: share/preparams/session-checkpoint interfaces

## Boundary

This SDK owns shared participant runtime contracts, not service-specific
orchestration APIs.

Owned by SDK:

- signed MPC runtime wire messages in `protocol`
- participant runtime state machine in `participant`
- host-provided identity/storage interfaces
- external cosigner gateway stream API in `api/gateway/v1`

Not owned by SDK:

- orch client APIs such as keygen/sign request submission
- orch request response envelopes such as accepted/rejected responses
- Apex registry, cosigner revoke records, public key version records, or wallet
  session storage models
- service transport choices such as NATS subjects or HTTP routes
- mobile app/runtime packaging; that now lives in `cosigner-mobile`

If a type is needed because multiple participant runtimes must parse, validate,
sign, or verify the same bytes, it belongs in SDK. If a type describes service
admission, product state, storage, or backend client submission, it belongs in
that service repo.

Mobile-specific bindings and app runtime live in the sibling
`cosigner-mobile` repo. Its gomobile module imports this SDK for the shared MPC
runtime contracts.

## Private module access

For private GitHub modules in the same org, configure Go to skip the public
module proxy and let Git rewrite HTTPS module fetches to SSH:

```sh
go env -w GOPRIVATE=github.com/fystack/*
git config --global url."git@github.com:fystack/".insteadOf "https://github.com/fystack/"
```

## Minimal integration example

Below is a minimal orchestrator-to-participant integration skeleton.

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
// - identity.OrchestratorLookup
// - storage.PreparamsStore / ShareStore / SessionCheckpointStore

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

	// 2) Handle control from Orchestrator:
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

// Orchestrator signing reminder:
// - Build control payload using protocol.ControlSigningBytes(msg)
// - Sign bytes with orchestrator private key (ed25519)
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
  - Each session pins one slot in its local `SessionCheckpoint`, so in-flight sessions are deterministic across global rotates.
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

## Notes

- `RESHARE` is not implemented yet.
- Mobile bindings and app integration live in `cosigner-mobile`.
