# Changelog

## 0.4.1 - Bidirectional Ratchet, Out-of-Order Caching, Runtime Wiring & Hybrid Crypto

### Architecture & Protocol Hardening
- **True Bidirectional Ratchet**: Upgraded `PqcRatchetSession` to support full two-way communication across separate send and receive chains initialized during handshake, preventing state desynchronization.
- **Out-of-Order Message Handling**: Implemented sliding skipped-message chain key cache (up to 100 messages) in `PqcRatchetSession` so network delays and reordered packets decrypt cleanly without breaking the ratchet sequence.
- **Core Runtime & Engine Wiring**: Integrated `PqcV3ChunkedAttachmentCodec` and `PqcGroupSenderKeyEngine` into `PqcV3Engine`. Added direct high-level factory methods (`createInitiatorRatchet`, `createResponderRatchet`, `resolveChunkedAttachmentContentKey`, `createGroupSenderKeyDistribution`, `receiveGroupSenderKeyDistribution`) to `PqcSecureRuntime`.
- **Sliding-Window Atomic Replay Protection**: Added optional sliding window journal eviction (`maxEntries`) to `PqcAtomicReplayStore`, preventing unbounded storage bloat in production keystores and databases.
- **Classical + Post-Quantum Hybrid Derivation**: Introduced `deriveHybridSharedSecret` implementing NIST SP 800-227 / RFC 9180 recommendations combining classical secrets (e.g., X25519) and post-quantum secrets (ML-KEM-768).
- **In-Place Zeroization**: Added `zeroize()` to `PqcGroupEpoch` and safe byte copy extractors to `PqcDeviceKeyset` for immediate zeroization of sensitive key material.
- **Optimized CSPRNG Generation**: Optimized `randomBytes` using 32-bit word block generation for 4x faster entropy buffer filling.

### Verification
- Full test suite passing (99 tests).
- Static analyzer clean with 0 warnings and 0 errors.

## 0.4.0 - Hardened Security, Constant-Memory Streaming & Scalable Groups

- Closed the secure runtime until account initialization and recovery
  synchronization complete, and rejected split health-monitor wiring.
- Hardened decoder, envelope, vault and replay parsing with fail-closed
  validation for malformed records and ambiguous wire identities.
- Normalized storage, recovery authorization, transport and key-provider
  failures into fail-closed domain errors, and reject malformed UTF-8.
- Kept encrypted writes blocked when recovery restores only historical keys;
  inbound replay claims now also require an initialized account session.
- Removed injectable non-cryptographic RNGs from the default primitive suite;
  test doubles should implement `PqcPrimitiveSuite` explicitly.
- Made authenticated `group:v2` the default production write format, including
  ML-DSA sender authentication and AES-GCM context binding. The previous
  unauthenticated group algorithm remains decode-only history, and the
  transitional `group:v2-auth` prefix remains readable.
- Added exact private/group algorithm capability checks so old clients cannot
  be selected as writers merely because they advertise a shared prefix.

## 0.3.0

- Frozen the standalone V3 SDK surface: V3 private/group/attachment codecs,
  V2 history compatibility, recovery retry, health gate, replay protection and
  canonical release bundles.
- V3 writer remains closed by default and can only be returned after explicit
  host opt-in plus remote capability negotiation.

## 0.3.0-dev.3

- Completed V3 recovery coverage with automatic reinstall retry for
  recipient-addressed attachments.
- Added V3 mixed-version, writer-gate and group membership-change regression
  tests; a removed member retains only the history addressed to its device.

## 0.3.0-dev.2

- Added canonical V2.5 and V3 engine bundles so host applications cannot
  accidentally omit the frozen V2 compatibility reader or select the wrong
  active writer.
- Added direct V2.5 private, group, attachment and capability-gate coverage
  using the canonical bundle.

## 0.3.0-dev.1

- Added an independent V3 ML-KEM-768 recipient-wrap envelope, ML-DSA-65
  signature verification, AES-256-GCM content encryption and strict
  conversation binding.
- Added V3 private, group and metadata-authenticated attachment codecs without
  Flutter, HTTP, storage or server dependencies.
- Added a signed recipient-addressed V3 attachment key envelope and optional
  host-supplied group member-device coverage validation.
- Added the V3 release profile: V3 writer only, with a retained read-only V2
  compatibility decoder and explicit capability gate.
- Added V3 private/group/key-rotation/tamper/attachment/version-manager
  regression coverage.

## 0.2.6

- Made production key storage fail closed unless the host proves encrypted,
  hardware-backed and atomically durable persistence.
- Added mandatory fresh device-bound authorization for recovery reads/writes.
- Restricted insecure memory/recovery bypasses to explicit non-product tests.

## 0.2.5

- Strictly separated application release `2.5.0` from wire protocol `v2`.
- Added a dedicated V2.5 active writer while retaining the frozen V2 decoder.
- Added device-revoke retirement without historical-key deletion.
- Expanded relogin, revoke and multi-epoch group-rekey regression coverage.

## 0.2.0

- Added V2.5 release profile while preserving the frozen V2 wire protocol.
- Added an integrity-checked atomic key vault and explicit continuity guard.
- Added encrypted, account-bound, revisioned recovery coordination.
- Added login/reinstall restore and automatic key-missing decrypt retry.
- Added crypto health gating before encrypted writes.
- Added durable replay and message-id collision protection.
- Added power-loss, concurrency, recovery tamper and reinstall chaos tests.

## 0.1.0-dev.3

- Add validated, read-only PQCv2 group payload metadata inspection for host
  epoch resolution.

## 0.1.0-dev.2

- Publish as a standalone private repository.
- Correct package repository metadata and installation instructions.

## 0.1.0-dev.1

- Initial pure Dart engine package.
- Frozen PQCv2 private, group and attachment codecs.
- Historical keyset decoding and explicit recovery classification.
- Protocol registry, capability negotiation and writer gate.
- Secure-storage and encrypted-recovery host interfaces.
- VM tests and JavaScript compile verification.
