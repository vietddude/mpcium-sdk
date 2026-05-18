# SDK Structure

This document maps out the Go packages that make up `mpcium-sdk`, how they
depend on each other, and what each one is responsible for. It is meant
as a starting point before diving into any single file.

## What this SDK is

`mpcium-sdk` is the core participant-side runtime of an MPC (threshold
signature) system. It does not run an Orchestrator, a relay, a broker, or a
mobile app. It runs participant sessions and performs `tss-lib` rounds against
peers under the direction of an external Orchestrator.

The SDK entry point is:

- **Go / server integration** — import `participant` directly and drive
  sessions with your own transport and storage.

Mobile bindings and application integration moved to the sibling
`cosigner-mobile` repo. That repo imports this SDK for protocol, storage,
identity, participant runtime, and gateway stream contracts.

## Package layout

```
mpcium-sdk/
├── api/
│   └── gateway/v1/     external cosigner gateway gRPC API
├── protocol/           wire types, validation, signing bytes
├── identity/           ed25519 identity / peer lookup interfaces
├── storage/            preparams / share / session-checkpoint interfaces
├── internal/
│   └── wirecrypto/     X25519 + AEAD direct-packet encryption
├── participant/        session FSM on top of tss-lib
├── examples/           runnable integration skeletons
└── docs/               architecture notes
```

## Dependency graph

Arrows point in the direction of imports. Lower layers never import
higher ones.

```
              ┌────────────────────┐
              │  api/gateway/v1    │   external cosigner stream contract
              └────────────────────┘

               ┌──────────────┐      ┌──────────────────────┐
               │ participant  │      │  transport / store   │
               │ (session FSM,│      │  adapters provided   │
               │  tss-lib)    │      │  by the host app     │
               └─┬──┬──┬──────┘      └──────────────────────┘
                 │  │  │
       ┌─────────┘  │  └─────────────────────────┐
       │            │                            │
┌──────▼─────┐ ┌────▼──▼────┐         ┌──────────▼────────────┐
│  identity  │ │   storage  │         │  internal/wirecrypto  │
└──────┬─────┘ └──────┬─────┘         └──────────┬────────────┘
       │              │                          │
       └──────────────┴──────────┬───────────────┘
                                 │
                       ┌─────────▼──────────┐
                       │      protocol      │   (zero SDK deps)
                       └────────────────────┘
```

Key rule: `protocol` is the shared vocabulary at the bottom and must not
depend on any other SDK package. `participant` is the core of the SDK
and must not know about transports, event queues, mobile UI, or app lifecycle.
`api/gateway/v1` is a separate protobuf contract package for the external
cosigner gateway stream; it does not define orchestration request submission.

## Module purposes

| Package               | Purpose                                                                                                                                                                                                                                                                                                                                                   | Key types / files                                                 |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `api/gateway/v1`      | Protobuf/gRPC contract for the bidirectional stream between an external cosigner runtime and `cosigner-gateway`. It lives in SDK so external cosigners do not need to import the orchestrator repo. It is not the orch client API.                                                                                                                        | `CosignerGateway`, `GatewayControl`, gateway envelopes            |
| `protocol`            | Canonical JSON wire contracts between Orchestrator and participants: message types, validation rules, and signing-bytes helpers. Zero SDK deps so Orchestrator and participant can share it verbatim.                                                                                                                                                       | `types.go`, `validate.go`, `signing.go`                           |
| `identity`            | Abstract interfaces for the local ed25519 signing identity and for looking up peer / orchestrator public keys. The host app provides the implementation.                                                                                                                                                                                                   | `LocalIdentity`, `PeerLookup`, `OrchestratorLookup`                |
| `storage`             | Abstract interfaces for all persistent state the runtime needs: ECDSA preparams slots, key shares, and per-session resume checkpoints. Also host-provided.                                                                                                                                                                                                 | `PreparamsStore`, `ShareStore`, `SessionCheckpointStore`          |
| `internal/wirecrypto` | Internal helper for direct (unicast) MPC packets: X25519 key agreement, HKDF, ChaCha20-Poly1305 encryption with envelope-bound AAD. Broadcast packets are sign-only and do not use this package.                                                                                                                                                          | `KeyPair`, `GenerateKeyPair`, `EncryptDirect`, `DecryptDirect`    |
| `participant`         | The core SDK: the session state machine that drives `tss-lib` rounds, handles `ControlMessage` / `PeerMessage`, emits `SessionEvent` and `Result`. Pure logic — no I/O, no timers, no transport. Also owns preparams-slot rotation.                                                                                                                       | `ParticipantSession`, `Actions`, `Config`, `RotatePreparamsSlot`  |
| `examples/`           | Runnable integration skeletons for SDK runtime usage.                                                                                                                                                                                                                                                                                                     | `examples/keygen_flow`                                            |
| `docs/`               | Architecture notes for the SDK runtime and boundary.                                                                                                                                                                                                                                                                                                      | `docs/architecture/*`                                             |

## Boundary rules

SDK owns contracts that participant runtimes must share exactly: signed runtime
wire messages, validation rules, signing bytes, participant state-machine APIs,
host identity/storage interfaces, and the external cosigner gateway stream API.

SDK does not own service-specific orchestration APIs. Keygen/sign submission
requests, accepted/rejected request responses, participant admission metadata,
Apex registry records, revoke state, public key versions, wallet/session DB
models, NATS subjects, HTTP routes, mobile UI, mobile storage wrappers, and app
runtime lifecycle belong to the service/app repos that expose or persist them.

Use this rule when deciding where a new type belongs: if multiple participant
runtimes must parse, validate, sign, verify, or relay the same bytes, put it in
SDK. If the type describes backend admission, product state, app storage,
mobile UI events, or client request submission to an orchestrator, keep it out
of SDK.

## Typical control + data flow

Host integration drives `ParticipantSession` with service-owned transport and
storage:

```
                       ┌──────────────┐
                       │ Orchestrator  │
                       └──────┬───────┘
                              │ signed ControlMessage
                              ▼
                       ┌──────────────┐        ┌──────────────┐
                       │  Transport   │ ◀────▶ │    Peers     │
                       │ (NATS / MQTT)│  signed│ (other SDK   │
                       └──────┬───────┘  Peer  │  participants)│
                              │          Msgs  └──────────────┘
                              ▼
                   ┌─────────────────────┐
                   │  ParticipantSession │      driven by:
                   │   (participant/)    │       Start()
                   │                     │       HandleControl(ctrl)
                   │   ┌─────────────┐   │       HandlePeer(peer)
                   │   │  tss-lib    │   │
                   │   │ keygen/sign │   │      returns Actions:
                   │   └─────────────┘   │       • PeerMessages
                   └──┬────────┬─────────┘       • SessionEvents
                      │        │                 • Result (terminal)
            identity  │        │  storage
         (sign/verify)│        │ (preparams,
                      ▼        ▼  shares,
               ┌────────┐ ┌─────────┐ checkpoints)
               │identity│ │ storage │
               └────────┘ └─────────┘
```

`ParticipantSession.Start / HandleControl / HandlePeer` return an
`Actions` value describing what the host should send next. The session
itself never touches the network. The host owns the transport.

## Sequence diagrams

These show how an integrator drives the SDK over time. The "Host app"
column is whatever your code is: a server process, gateway runtime, or
`cosigner-mobile` integration. Only the participant-side runtime contracts are
owned by this SDK; the Orchestrator and peers are external systems you must
provide.

### 1. Keygen session

The canonical flow. The Orchestrator picks a committee and a threshold;
participants exchange X25519 keys, then run `tss-lib` keygen rounds and
persist their share.

```
Orchestrator      Host app / Transport        ParticipantSession         Peers
     │                   │                            │                   │
     │─ControlMsg────────▶                            │                   │
     │  (SessionStart)   │                            │                   │
     │                   │─ ParticipantSession.New() ─▶                   │
     │                   │─ Start() ──────────────────▶                   │
     │                   │◀── Actions{PeerJoined,     │                   │
     │                   │           PeerReady events}│                   │
     │◀─SessionEvent─────│                            │                   │
     │  (PeerJoined,     │                            │                   │
     │   PeerReady)      │                            │                   │
     │                                                                    │
     │─ControlMsg────────▶                            │                   │
     │  (KeyExchangeBegin)                            │                   │
     │                   │─ HandleControl(ctrl) ──────▶                   │
     │                   │◀── Actions{KeyExchangeHello peer messages}     │
     │                   │──── signed KeyExchangeHello ─────────────────▶ │
     │                   │◀─── signed KeyExchangeHello ───────────────── │
     │                   │─ HandlePeer(hello) ────────▶                   │
     │                   │          ... per peer ...                      │
     │                   │◀── Actions{PeerKeyExchangeDone event}          │
     │◀─SessionEvent─────│                            │                   │
     │  (PeerKeyExchangeDone)                         │                   │
     │                                                                    │
     │─ControlMsg────────▶                            │                   │
     │  (MPCBegin)       │                            │                   │
     │                   │─ HandleControl(ctrl) ──────▶                   │
     │                   │                            │── tss-lib rounds ─▶
     │                   │◀── Actions{MPCPacket peer messages,            │
     │                   │           each encrypted if direct}            │
     │                   │── signed (+ encrypted) MPCPacket ─────────────▶│
     │                   │◀── signed (+ encrypted) MPCPacket ─────────── │
     │                   │─ HandlePeer(peer) ─────────▶                   │
     │                   │          ... many rounds ...                   │
     │                   │◀── Actions{SessionCompleted, Result.KeyShare}  │
     │                   │─ ShareStore.SaveShare() ──▶ (storage)          │
     │◀─SessionEvent─────│                            │                   │
     │  (SessionCompleted                             │                   │
     │   + KeyShareResult)                            │                   │
```

### 2. Sign session with host approval

Signing reuses an existing share. If a host requires approval before signing,
the host must collect that approval before it starts or continues the
participant runtime for the request.

```
Orchestrator      Host app / Transport        ParticipantSession         Peers
     │                   │                            │                   │
     │─ControlMsg────────▶                            │                   │
     │  (SessionStart,   │                            │                   │
     │   Operation=SIGN) │                            │                   │
     │                   │─ collect host approval ──▶ │                   │
     │                   │─ ParticipantSession.New() ─▶                   │
     │                   │─ Start() ──────────────────▶                   │
     │                   │◀── Actions{events}         │                   │
     │◀─SessionEvent─────│                            │                   │
     │                                                                    │
     │        (... key exchange + MPCBegin sequence same as keygen ...)   │
     │                                                                    │
     │                   │◀── Actions{SessionCompleted, Result.Signature} │
     │◀─SessionEvent─────│                            │                   │
```

Integration checklist for a host app:

1. Implement `identity.LocalIdentity` / `PeerLookup` /
   `OrchestratorLookup`.
2. Implement `storage.PreparamsStore`, `ShareStore`,
   `SessionCheckpointStore`.
3. Route `ControlMessage` into `ParticipantSession.HandleControl`, route
   `PeerMessage` into `HandlePeer`. Send everything in
   `Actions.PeerMessages` / `Actions.SessionEvents` out on your
   transport.
4. Persist `Result.KeyShare` when keygen completes; surface
   `Result.Signature` to the caller when signing completes.

## Reviewer cheat sheet

Things that matter when reviewing a change in this codebase.

### Security model & trust boundaries

The SDK assumes the **transport is untrusted** (an MQTT broker or NATS
server can be compromised, messages can be reordered, replayed, or
spoofed). It does **not** assume the Orchestrator is trusted to see MPC
payloads — it only trusts the Orchestrator to schedule sessions.

What protects what:

| Message class                         | Signed by                     | Encrypted?                                        | Replay protection              |
| ------------------------------------- | ----------------------------- | ------------------------------------------------- | ------------------------------ |
| `ControlMessage`                      | Orchestrator (ed25519)         | No                                                | `Sequence` monotonic check     |
| `PeerMessage` / `KeyExchangeHello`    | Sender participant (ed25519)  | No                                                | Covered by AEAD AAD            |
| `PeerMessage` / `MPCPacket` direct    | Sender participant (ed25519)  | Yes — ChaCha20-Poly1305, per-pair X25519-HKDF key | AEAD nonce + AAD over envelope |
| `PeerMessage` / `MPCPacket` broadcast | Sender participant (ed25519)  | No — signature only                               | Covered by signature           |
| `SessionEvent`                        | Emitter participant (ed25519) | No                                                | `Sequence` monotonic           |

Key crypto facts to verify in any change:

- **Signing bytes are canonical.** Must go through
  `protocol.ControlSigningBytes` / `PeerSigningBytes` /
  `SessionEventSigningBytes` on both sides. These clear `Signature` and
  JSON-marshal. Do not add new fields that the signer and verifier
  might serialise differently.
- **Direct packet AAD.** `wirecrypto.BuildAAD` re-marshals the
  `PeerMessage` envelope with `Signature`, `Payload`, and `Nonce`
  stripped. A change that reorders fields, adds new ones, or changes
  `MarshalJSON` behaviour will silently break decryption on one side —
  update both sides and the tests.
- **Per-pair session key derivation.**
  `derivePacketKey` = HKDF-SHA256 over the X25519 shared secret with
  `info = "mpcium-sdk/direct-v1:<sessionID>:<from>:<to>"`. The directed
  info string means (A→B) and (B→A) use **different** keys. Do not
  collapse that.
- **Broadcast messages carry no nonce and no ciphertext** — the SDK
  rejects anything else at `ValidatePeerMessage`. If you are tempted to
  "just encrypt broadcasts too", it changes the protocol.

### `wirecrypto` API surface and call sites

`internal/wirecrypto` is small and stateless — the entire surface is
exercised from exactly three places in `participant/session.go`. Use
this map when changing the package or its callers.

| Function                  | Called from                          | Use case                                                                                                                                          |
| ------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GenerateKeyPair`         | `session.go` `beginKeyExchange`      | Mints the participant's ephemeral X25519 keypair when the orchestrator sends `KeyExchangeBegin`. One keypair per session, never persisted.         |
| `KeyPair.PublicKeyBytes`  | `session.go` `beginKeyExchange`      | Embedded into the outgoing `KeyExchangeHello` so peers can derive the shared secret to this participant.                                          |
| `EncryptDirect`           | `session.go` `toPeerMessage` (sign)  | Encrypts an MPC round packet to a single recipient. Returns `(nonce, ciphertext)` that get attached to the outgoing `MPCPacket` before signing.   |
| `DecryptDirect`           | `session.go` `decryptDirectPacket`   | Decrypts an inbound MPC packet inside `HandlePeer`. Output is fed to `tss-lib` via `party.UpdateFromBytes`.                                       |
| `BuildAAD`                | wirecrypto-internal                  | Helper used by `EncryptDirect` / `DecryptDirect` to derive the envelope-bound AAD. Not called by `participant`.                                   |

End-to-end view of how those calls compose during one session:

```
Orchestrator → KeyExchangeBegin
        │
        ▼
beginKeyExchange()
        ├── wirecrypto.GenerateKeyPair()        ← mint ephemeral X25519 keypair
        └── localKey.PublicKeyBytes()           ← extract pubkey for the wire
                │
                ▼
        KeyExchangeHello sent to every peer
                │
        Peers reply → s.peerX25519Pub[from] = pub

(key exchange done — derived keys are now per-pair via HKDF)

Outbound MPC packet (toPeerMessage, direct only):
        wirecrypto.EncryptDirect(localKey, peerPub, msg, payload)
                returns (nonce, ciphertext)
        → attached to msg.MPCPacket → Ed25519 sign → send

Inbound MPC packet (HandlePeer → decryptDirectPacket):
        wirecrypto.DecryptDirect(localKey, peerPub, msg, nonce, ciphertext)
                returns plaintext
        → s.party.UpdateFromBytes(plaintext, ...)
```

Things to keep true when changing this surface:

- `wirecrypto` is `internal/` for a reason — only `participant` should
  import it. Do not re-export it from app/runtime packages.
- No persistent state lives in `wirecrypto`. The X25519 keypair is owned
  by `ParticipantSession.kxLocalKey` and discarded on session end /
  restart (see `loadCheckpoint`, which sets `kxLocalKey = nil` and forces
  a fresh key exchange). Adding a "restore key from bytes" API would
  invite reuse of an ephemeral key across sessions — don't.
- `BuildAAD` is the *one* place that defines what envelope fields are
  channel-bound. Adding fields to `PeerMessage` automatically extends
  AAD coverage; removing or reordering fields silently breaks
  compatibility with any peer running an older version. Treat changes
  to `PeerMessage` as wire-format changes (see Wire format stability).

### Session state machine

`ParticipantSession` moves through these phases (see
`ParticipantPhase` in `protocol/types.go`):

```
   New() ── validates SessionStart ──▶ CREATED
                                         │
                                         ▼  Start()
                                      JOINING ── emits PeerJoined ──▶ READY
                                         │
                       HandleControl(KeyExchangeBegin)
                                         │
                                         ▼
                                   KEY_EXCHANGE ── exchange X25519 ──▶ KEY_EXCHANGE_DONE
                                         │
                           HandleControl(MPCBegin)
                                         │
                                         ▼
                                   MPC_RUNNING ── tss-lib rounds ──▶ COMPLETED
                                         │                         └─▶ FAILED / ABORTED
```

Invariants the runtime enforces (reject changes that break these):

1. `MPCBegin` before `KEY_EXCHANGE_DONE` → `ErrKeyExchangeRequired`.
2. Two `SessionStart`s for the same session, or mismatched `SessionID`
   between envelope and body → rejected by `ValidateControlMessage`.
3. Control `Sequence` must be strictly increasing per session —
   `controlSeqSeen` guards against replay / reordering.
4. A `PeerMessage` whose `Phase` disagrees with what the local session
   is waiting for is dropped.
5. Once a session hits `COMPLETED` / `FAILED` / `ABORTED`, further
   `Handle*` calls are no-ops (or errors) — the session is terminal.

### Concurrency model

This is easy to get wrong when adding features. The contract today:

- **`ParticipantSession` is NOT goroutine-safe.** It has no locks.
  Callers must serialise `Start` / `HandleControl` / `HandlePeer` per
  session (one goroutine per session, or a mutex you own).
- Host runtimes that run sessions concurrently must own their own locking,
  queues, and lifecycle cancellation. SDK packages do not start background
  transport goroutines for the host.
- `protocol` signing helpers are stateless. Callers still need to serialize
  per-session control and peer handling so sequence checks remain meaningful.

### Preparams slot model (ECDSA keygen only)

ECDSA keygen is expensive. The SDK stores preparams in named slots so they can
be pre-generated, rotated, and pinned per-session:

- `PreparamsStore` interface: `Load/SavePreparamsSlot(protocol, slot)`,
  `Load/SaveActivePreparamsSlot(protocol)`.
- Runtime resolution order per session: **pinned slot** (from
  `SessionCheckpoint`) → **active slot** → hard failure. No silent
  regeneration.
- Each session pins the slot it will use into its local
  `SessionCheckpoint` at start, so a global rotation mid-session does
  not change its inputs.
- On successful ECDSA keygen the session writes fresh preparams to slot
  `next`, then calls `RotatePreparamsSlot` which:
  1. Decode-validates `next`.
  2. Snapshots the current active into slot `prev`.
  3. Atomically points active → `next`.
  4. Reads active back and asserts it matches.

Gotchas:

- Never call `SaveActivePreparamsSlot` directly from new code — go
  through `RotatePreparamsSlot` so the decode health-check runs.
- A missing or empty active slot is a **fast-fail** condition
  (`ErrPreparamsSlotMissing`, `ErrPreparamsBlobMissing`). Integrators
  must seed at least one valid slot before running keygen.

### Wire format stability

The JSON encoding **is** the protocol. Both the Orchestrator and the
participants serialise and re-serialise the same Go types, and
signatures + AEAD AAD cover the exact bytes. Consequences:

- Any field added to `ControlMessage`, `PeerMessage`, `SessionEvent`
  (or their embedded bodies) changes the bytes that get signed. Old
  peers will reject new fields' signatures once you populate them.
- Renaming a JSON tag silently breaks compatibility.
- `omitempty` / pointer-vs-value matters: emitting `"field":null` vs.
  omitting the key produces different bytes and different signatures.
- Treat the types in `protocol/` as versioned. If you need a breaking
  change, plan for a new top-level type or a version field, not a
  silent edit.
- Do not add orch request/response DTOs to `protocol/`. Request acceptance,
  rejection, and participant admission descriptors are orchestration API
  concerns, not participant runtime wire protocol.

### Not yet implemented / known gaps

- **RESHARE** is plumbed through `protocol` and `validate.go` but the
  session runtime does not execute the reshare rounds yet. Do not
  claim feature completeness for reshare in docs or examples.
- **Transport backends** (NATS / MQTT clients) are host-provided. The
  SDK ships runtime contracts only; authentication, TLS, and reconnect logic
  all live in the host transport.
- **Mobile bindings** are out of this repo. Use `cosigner-mobile` for mobile
  gomobile bindings and app integration.

### Testing map

Useful when reviewing a test or checking coverage of a change:

| What                                  | Where                                     |
| ------------------------------------- | ----------------------------------------- |
| Protocol validation rules             | `protocol/validate_test.go`               |
| Direct-packet encryption / AAD tamper | `internal/wirecrypto/wirecrypto_test.go`  |
| End-to-end session (multi-party)      | `participant/session_integration_test.go` |
| Preparams rotation                    | `participant/preparams_rotation_test.go`  |
| Session + preparams interaction       | `participant/session_preparams_test.go`   |

### Things reviewers should always check

- Was a new field added to a `protocol/` type? If so, did the signing
  bytes and AAD computation stay in sync on both producer and consumer?
- Did a new `ControlMessage` / `PeerMessage` / `SessionEvent` body get
  added? If so, is there a `ValidateXxx` branch and a `bodyCount`
  increment?
- Did someone start storing more data under `SessionCheckpoint`? The
  format is gob-encoded — schema changes need a migration story.
- Did a change introduce a new panic path? Public SDK packages must not panic
  under host misuse — convert to returned errors.
- Any silent-swallow of errors from `tss-lib`? Those should emit
  `SessionFailed` with a `FailureReason`, not be logged and dropped.

## Layering rules

1. `protocol` is the bottom. Everyone can import it. It imports nothing
   from this module.
2. `api/gateway/v1` is a standalone external cosigner stream contract. It may
   be imported by gateway and cosigner runtimes, but it must not import SDK
   runtime packages or service repos.
3. `identity`, `storage`, `internal/wirecrypto` sit above `protocol` and
   below `participant`. They are all narrow-purpose.
4. `participant` is the core. It must stay free of transport, event
   queues, and mobile concerns. App/runtime concerns belong to `cosigner-mobile`
   or other host repos.
5. `examples/` depends on public packages only; nothing else depends on
   `examples/`.

## Where to start reading

- Wire format & validation → `protocol/types.go`, `protocol/validate.go`
- External cosigner gateway stream → `api/gateway/v1/gateway.proto`
- Session state machine → `participant/session.go`
- End-to-end example → `examples/keygen_flow/main.go`
