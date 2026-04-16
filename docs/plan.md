# Thin `tss-lib` Wrapper for Server, Mobile, and TEE

## Summary
Build a thin orchestration layer on top of [`bnb-chain/tss-lib`](https://github.com/bnb-chain/tss-lib) that standardizes session handling, compact envelope encoding, and opaque key material persistence, while leaving networking, E2E security, retries, and reliable broadcast to the caller. This matches the upstream model: transport is application-owned, outbound messages come from `WireBytes()`, inbound messages go through `UpdateFromBytes(...)`, and `WireMsg()` exists mainly for exceptional/mobile cases.

v1 scope is fixed as:
- `ECDSA` and `EdDSA`
- `keygen` and `sign`
- step-based session API
- compact binary envelope carrying raw `tss-lib` message bytes
- opaque blob storage interface
- no resharing, no built-in network stack, no custom message compression

## Key Changes
### 1. Cross-runtime core API
Expose a FFI-safe core package whose public surface is data-in/data-out, not channels or callbacks.

Public concepts:
- `Protocol`: `ECDSA | EdDSA`
- `Operation`: `Keygen | Sign`
- `SessionConfig`:
  - `session_id` as fixed 16-byte value
  - `protocol`
  - `operation`
  - ordered participant list with stable dense indexes
  - local participant index
  - threshold
  - signer set for `Sign`
  - message digest for `Sign`
- `Session` methods:
  - `Start() -> outbound_batch, terminal_result?, error`
  - `Apply(inbound_envelope_bytes) -> outbound_batch, terminal_result?, error`
  - `WaitingFor() -> participant_indexes`
  - `Status() -> round state / done / failed`

Implementation detail: the wrapper internally owns `LocalParty`, `outCh`, and `endCh`, but those are never exposed publicly.

### 2. Compact envelope format
Define one canonical binary envelope format for all runtimes.

Envelope fields:
- `version` `u8`
- `protocol` `u8`
- `operation` `u8`
- `flags` `u8` with broadcast bit
- `session_id` `[16]byte`
- `from_index` `u16`
- `recipient_count` `u8`
- `recipient_indexes` repeated `u16`
- `payload_len` `u32`
- `payload` raw `tss-lib` `WireBytes()`

Rules:
- no outer JSON
- no outer protobuf
- no peer string IDs on wire
- no re-encoding of `tss-lib` payload
- participant string IDs and unique keys stay local in the session config and are used only to build `*tss.PartyID` maps

### 3. Storage boundary
Use one opaque blob store interface; wrapper owns serialization, caller owns secure persistence.

Public boundary:
- `BlobStore.Load(ref) -> []byte`
- `BlobStore.Save(ref, []byte)`

Stored material:
- preparams blobs
- key share blobs

Reference naming is fixed:
- `preparams/<protocol>/<party_index>`
- `share/<protocol>/<key_id>/<party_index>`

The wrapper must reject loading blobs with mismatched protocol or operation context.

### 4. Optional Go transport helper
Provide an optional Go-only helper around the core API for server deployments.

Public interface:
- `Send(ctx, [][]byte) error`
- `Recv(ctx) ([]byte, error)`

This helper only pumps encoded envelopes between a `Session` and caller transport. It does not implement:
- TLS / Noise / AEAD
- peer auth
- replay protection across transport hops
- reliable broadcast
- retries / backoff
- session negotiation

Those remain explicit caller responsibilities.

## Implementation Notes
- Use the ordered participant list to build a stable local map: `participant_index -> *tss.PartyID`.
- Outbound routing comes directly from `tss-lib` message routing metadata; the wrapper converts it into recipient indexes in the envelope.
- Inbound validation happens before calling `UpdateFromBytes(...)`:
  - version match
  - session ID match
  - protocol match
  - operation match
  - sender index is known
  - local party is an intended recipient or message is broadcast
- `Keygen` terminal result is an opaque share blob plus optional persisted preparams blob.
- `Sign` terminal result is a compact signature result object containing signature bytes and algorithm-specific fields from upstream.
- `WireMsg()` is not part of the default path; raw `WireBytes()` stays the default because it keeps the wrapper thinner and smaller on the wire.

## Test Plan
- 2-of-3 `ECDSA` keygen completes across three local sessions and persists share blobs.
- 2-of-3 `ECDSA` sign completes using persisted share blobs and returns a valid signature.
- 2-of-3 `EdDSA` keygen and sign complete with the same session API.
- Envelope binary marshal/unmarshal round-trips exactly.
- Session mismatch, protocol mismatch, operation mismatch, and unknown sender are rejected before reaching `tss-lib`.
- Broadcast and directed-routing metadata are preserved correctly through wrapper encoding.
- Loading a wrong blob type or wrong protocol blob fails deterministically.
- Public core API contains no channels/callbacks and is usable from a mobile/FFI facade.
- Go transport helper can drive an end-to-end in-memory harness without adding protocol logic.

## Assumptions
- Base library is [`bnb-chain/tss-lib`](https://github.com/bnb-chain/tss-lib); visible latest release on the repo page is `v2.0.2` dated January 16, 2024.
- v1 intentionally excludes resharing.
- v1 intentionally excludes built-in compression; if needed later, compression is added at the transport layer, not by replacing `tss-lib` payload encoding.
- Reliable broadcast and end-to-end secure channels are mandatory but remain outside the wrapper.
