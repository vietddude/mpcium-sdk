# SDK Structure

This document maps out the Go packages that make up `mpcium-sdk`, how they
depend on each other, and what each one is responsible for. It is meant
as a starting point before diving into any single file.

## What this SDK is

`mpcium-sdk` is the **participant-side** runtime of an MPC (threshold
signature) system. It does not run a coordinator, a relay, or a broker.
It runs on a single participant's machine (server, mobile, or desktop)
and performs `tss-lib` rounds against peers under the direction of an
external coordinator.

Two entry points are provided:

- **Go / server integration** — import `participant` directly and drive
  sessions with your own transport and storage.
- **Mobile integration** — import `mobile` (a `gomobile`-compatible
  JSON facade) which wraps `mobilecore` for Android/iOS apps.

## Package layout

```
mpcium-sdk/
├── protocol/           wire types, validation, signing bytes
├── identity/           ed25519 identity / peer lookup interfaces
├── storage/            preparams / share / session-checkpoint interfaces
├── internal/
│   └── wirecrypto/     X25519 + AEAD direct-packet encryption
├── participant/        session FSM on top of tss-lib
├── mobilecore/         runtime wiring (transport, stores, events)
├── mobile/             gomobile JSON facade (Android/iOS)
├── examples/           runnable integration skeletons
└── docs/               architecture notes
```

## Dependency graph

Arrows point in the direction of imports. Lower layers never import
higher ones.

```
                        ┌───────────────────────────┐
                        │          mobile           │   gomobile JSON facade
                        └───────────────┬───────────┘
                                        │
                        ┌───────────────▼───────────┐
                        │         mobilecore        │   runtime + adapters +
                        │  (Runtime, Relay, Stores, │   event queue + topics
                        │   config, events, topics) │
                        └──┬────────────┬───────────┘
                           │            │
               ┌───────────▼──┐     ┌───▼──────────────────┐
               │  participant │     │  (transport / store  │
               │   (session   │     │   adapters provided  │
               │    FSM, tss) │     │   by the host app)   │
               └─┬──┬──┬──┬───┘     └──────────────────────┘
                 │  │  │  │
       ┌─────────┘  │  │  └──────────────────────┐
       │            │  │                         │
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
and must not know about mobile, transports, or event queues.

## Module purposes

| Package               | Purpose                                                                                                                                                                                                                                                                                                                                                   | Key types / files                                                 |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `protocol`            | Canonical JSON wire contracts between coordinator and participants: message types, validation rules, and signing-bytes helpers. Zero SDK deps so coordinator and participant can share it verbatim.                                                                                                                                                       | `types.go`, `validate.go`, `signing.go`                           |
| `identity`            | Abstract interfaces for the local ed25519 signing identity and for looking up peer / coordinator public keys. The host app provides the implementation.                                                                                                                                                                                                   | `LocalIdentity`, `PeerLookup`, `CoordinatorLookup`                |
| `storage`             | Abstract interfaces for all persistent state the runtime needs: ECDSA preparams slots, key shares, and per-session resume checkpoints. Also host-provided.                                                                                                                                                                                                 | `PreparamsStore`, `ShareStore`, `SessionCheckpointStore`          |
| `internal/wirecrypto` | Internal helper for direct (unicast) MPC packets: X25519 key agreement, HKDF, ChaCha20-Poly1305 encryption with envelope-bound AAD. Broadcast packets are sign-only and do not use this package.                                                                                                                                                          | `KeyPair`, `GenerateKeyPair`, `EncryptDirect`, `DecryptDirect`    |
| `participant`         | The core SDK: the session state machine that drives `tss-lib` rounds, handles `ControlMessage` / `PeerMessage`, emits `SessionEvent` and `Result`. Pure logic — no I/O, no timers, no transport. Also owns preparams-slot rotation.                                                                                                                       | `ParticipantSession`, `Actions`, `Config`, `RotatePreparamsSlot`  |
| `mobilecore`          | Wires `participant` sessions to a transport (`Relay` interface, with a `nativeRelay` wrapper that adapts any host-provided `TransportAdapter` — MQTT, NATS, etc.), a keyvalue store (`StoreAdapter`), coordinator identity lookup, topic naming, and an in-memory event queue for the host UI. Handles presence, approval prompts, and session lifecycle. | `Runtime`, `Relay`, `Stores`, `Config`, `RuntimeEvent`, topics.go |
| `mobile`              | Thin `gomobile`-compatible facade over `mobilecore`. Exposes a JSON-string API (`NewClient`, `Start`, `PollEvents`, `ApproveSign`, …) and lets the host register `TransportAdapter` and `StoreAdapter` implementations written in Kotlin/Swift.                                                                                                           | `Client`, `TransportAdapter`, `StoreAdapter`                      |
| `examples/`           | Runnable integration skeletons: `keygen_flow` for a server-style Go integration, `mobile-android` for the Android host that consumes the gomobile `.aar`.                                                                                                                                                                                                 | `examples/keygen_flow`, `examples/mobile-android`                 |
| `docs/`               | Architecture notes (this file, external/mobile cosigner runtime design).                                                                                                                                                                                                                                                                                  | `docs/architecture/*`                                             |

## Typical control + data flow

Server-style integration (mobile is the same flow with `mobile.Client`
and `mobilecore.Runtime` in front of `ParticipantSession`):

```
                       ┌──────────────┐
                       │ Coordinator  │
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
itself never touches the network — the host (or `mobilecore.Runtime`)
owns the transport.

## Sequence diagrams

These show how an integrator drives the SDK over time. The "Host app"
column is whatever your code is — a server process, `mobilecore`, or a
mobile runtime. Only the participant-side is owned by this SDK; the
coordinator and peers are external systems you must provide.

### 1. Keygen session

The canonical flow. The coordinator picks a committee and a threshold;
participants exchange X25519 keys, then run `tss-lib` keygen rounds and
persist their share.

```
Coordinator      Host app / Transport        ParticipantSession         Peers
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

### 2. Sign session (with mobile approval)

Signing reuses an existing share. On mobile, the host runtime
(`mobilecore.Runtime`) prompts the user before the session actually
starts — if the user declines or the approval times out, the SDK sends
back `RequestRejected` and never runs the MPC rounds.

```
Coordinator    mobile.Client    mobilecore.Runtime    ParticipantSession    Peers
     │              │                   │                      │             │
     │─ControlMsg──▶│                   │                      │             │
     │ (SessionStart                    │                      │             │
     │  Operation=SIGN)                 │                      │             │
     │              │─ deliver ────────▶│                      │             │
     │              │                   │─ enqueue event ─▶ RuntimeEvent     │
     │              │                   │  "sign_approval_required"          │
     │              │◀── PollEvents() ──│                      │             │
     │         (Host UI shows prompt to user)                  │             │
     │              │─ ApproveSign(sid, true, "") ─▶           │             │
     │              │                   │─ ParticipantSession.New() ─▶       │
     │              │                   │─ Start() ────────────▶             │
     │              │                   │◀── Actions{events} ──               │
     │◀──RequestAccepted / SessionEvent ◀── emit ──            │             │
     │              │                                           │             │
     │        (… key exchange + MPCBegin sequence same as keygen …)          │
     │              │                   │                      │             │
     │              │                   │◀── Actions{SessionCompleted,       │
     │              │                   │           Result.Signature}        │
     │◀─SessionEvent (SessionCompleted + SignatureResult)      │             │
     │              │─ PollEvents() ───▶│                      │             │
     │              │◀── "session_completed" ──                │             │
```

### 3. Mobile host integration (gomobile facade)

Shows how an Android/iOS host app talks to the SDK. The host owns the
real network socket (`TransportAdapter`) and the real disk
(`StoreAdapter`); the SDK drives them.

```
Android/iOS app              mobile.Client          mobilecore.Runtime
      │                           │                          │
      │─ NewClient(configJSON) ──▶│                          │
      │─ RegisterTransportAdapter(mqttAdapter)               │
      │─ RegisterStoreAdapter(keystoreAdapter)               │
      │─ Start() ─────────────────▶                          │
      │                           │─ wire adapters, start ──▶│
      │                           │                          │─ Relay.Subscribe(control, p2p, events)
      │                           │                          │─ start presence heartbeat
      │◀── PollEvents(max) ───────│                          │
      │  [{"type":"runtime_started"}, ...]                   │
      │                                                      │
      │  (user opens app; peers come online)                 │
      │                                                      │
      │◀── PollEvents(max) ───────│◀── "presence_online" ───│
      │                                                      │
      │  (coordinator triggers a sign)                       │
      │◀── PollEvents(max) ───────│◀── "sign_approval_required"
      │                                                      │
      │─ ApproveSign(sid, true, "") ─▶                       │
      │                           │─ approve ───────────────▶│─ run ParticipantSession
      │                                                      │
      │◀── PollEvents(max) ───────│◀── "session_completed"  │
      │                                                      │
      │─ Stop() ──────────────────▶                          │
```

Integration checklist for a host app:

1. Implement `identity.LocalIdentity` / `PeerLookup` /
   `CoordinatorLookup` (server) **or** provide `TransportAdapter` +
   `StoreAdapter` (mobile).
2. Implement `storage.PreparamsStore`, `ShareStore`,
   `SessionCheckpointStore` (server) **or** let `mobilecore` back them
   with your `StoreAdapter` (mobile).
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
spoofed). It does **not** assume the coordinator is trusted to see MPC
payloads — it only trusts the coordinator to schedule sessions.

What protects what:

| Message class                         | Signed by                     | Encrypted?                                        | Replay protection              |
| ------------------------------------- | ----------------------------- | ------------------------------------------------- | ------------------------------ |
| `ControlMessage`                      | Coordinator (ed25519)         | No                                                | `Sequence` monotonic check     |
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
| `GenerateKeyPair`         | `session.go` `beginKeyExchange`      | Mints the participant's ephemeral X25519 keypair when the coordinator sends `KeyExchangeBegin`. One keypair per session, never persisted.         |
| `KeyPair.PublicKeyBytes`  | `session.go` `beginKeyExchange`      | Embedded into the outgoing `KeyExchangeHello` so peers can derive the shared secret to this participant.                                          |
| `EncryptDirect`           | `session.go` `toPeerMessage` (sign)  | Encrypts an MPC round packet to a single recipient. Returns `(nonce, ciphertext)` that get attached to the outgoing `MPCPacket` before signing.   |
| `DecryptDirect`           | `session.go` `decryptDirectPacket`   | Decrypts an inbound MPC packet inside `HandlePeer`. Output is fed to `tss-lib` via `party.UpdateFromBytes`.                                       |
| `BuildAAD`                | wirecrypto-internal                  | Helper used by `EncryptDirect` / `DecryptDirect` to derive the envelope-bound AAD. Not called by `participant`.                                   |

End-to-end view of how those calls compose during one session:

```
Coordinator → KeyExchangeBegin
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
  import it. Do not re-export it from `mobile/` or `mobilecore/`.
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
- **`mobilecore.Runtime` IS goroutine-safe.** It fans out to per-session
  goroutines itself and holds `sessionsMu`, `seqMu`, `pendingMu` to
  protect its own maps. Do not grab those locks from outside the
  package.
- **`mobilecore.eventQueue`** (in `events.go`) is the bridge between SDK
  goroutines and the host's `PollEvents` caller — it has its own mutex.
- **`nativeRelay`** holds `mu` over a `handlers` map. The host's
  `TransportAdapter` must be safe to call from the relay's goroutines;
  the docstring on `TransportAdapter` should be the source of truth
  for host implementors.

If you add a new background goroutine in `mobilecore`, it must be tied
to the runtime lifecycle (`Start` / `Stop`) and must not outlive it —
otherwise `PollEvents` after `Stop` can block or panic.

### Preparams slot model (ECDSA keygen only)

ECDSA keygen is expensive (preparams generation alone is ~30s on mobile
hardware). The SDK stores preparams in named slots so they can be
pre-generated, rotated, and pinned per-session:

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

The JSON encoding **is** the protocol. Both the coordinator and the
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

### Not yet implemented / known gaps

- **RESHARE** is plumbed through `protocol` and `validate.go` but the
  session runtime does not execute the reshare rounds yet. Do not
  claim feature completeness for reshare in docs or examples.
- **iOS** runtime integration is out of scope for v1 (see README).
  `mobile/` is written for `gomobile` and has been exercised on Android.
- **Transport backends** (NATS / MQTT clients) are host-provided. The
  SDK ships only the generic adapter wrapper; authentication, TLS, and
  reconnect logic all live in the host's `TransportAdapter`.

### Testing map

Useful when reviewing a test or checking coverage of a change:

| What                                  | Where                                     |
| ------------------------------------- | ----------------------------------------- |
| Protocol validation rules             | `protocol/validate_test.go`               |
| Direct-packet encryption / AAD tamper | `internal/wirecrypto/wirecrypto_test.go`  |
| End-to-end session (multi-party)      | `participant/session_integration_test.go` |
| Preparams rotation                    | `participant/preparams_rotation_test.go`  |
| Session + preparams interaction       | `participant/session_preparams_test.go`   |
| Mobile runtime wiring                 | `mobilecore/runtime_test.go`              |
| Mobile JSON facade                    | `mobile/client_test.go`                   |

### Things reviewers should always check

- Was a new field added to a `protocol/` type? If so, did the signing
  bytes and AAD computation stay in sync on both producer and consumer?
- Did a new `ControlMessage` / `PeerMessage` / `SessionEvent` body get
  added? If so, is there a `ValidateXxx` branch and a `bodyCount`
  increment?
- Did someone add a background goroutine in `mobilecore`? Is it tied
  to `Runtime.Stop`?
- Did someone start storing more data under `SessionCheckpoint`? The
  format is gob-encoded — schema changes need a migration story.
- Did a change introduce a new panic path? Public API in `mobile/` and
  `mobilecore/` must not panic under host misuse — convert to returned
  errors.
- Any silent-swallow of errors from `tss-lib`? Those should emit
  `SessionFailed` with a `FailureReason`, not be logged and dropped.

## Layering rules

1. `protocol` is the bottom. Everyone can import it. It imports nothing
   from this module.
2. `identity`, `storage`, `internal/wirecrypto` sit above `protocol` and
   below `participant`. They are all narrow-purpose.
3. `participant` is the core. It must stay free of transport, event
   queues, and mobile concerns — those belong to `mobilecore`.
4. `mobilecore` assembles a concrete runtime. It is the only place that
   knows about presence heartbeats, MQTT, approval timeouts, and the
   host-facing event queue.
5. `mobile` is a JSON-in / JSON-out facade for `gomobile`. It adds no
   MPC logic.
6. `examples/` depends on public packages only; nothing else depends on
   `examples/`.

## Where to start reading

- Wire format & validation → `protocol/types.go`, `protocol/validate.go`
- Session state machine → `participant/session.go`
- Mobile runtime wiring → `mobilecore/runtime.go`
- Public mobile API → `mobile/client.go`
- End-to-end example → `examples/keygen_flow/main.go`
