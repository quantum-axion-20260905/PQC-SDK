# PQC Engine SDK

Pure Dart post-quantum cryptography engine for Axion products and licensed
integrators. It contains cryptographic protocol code only. It has no Flutter,
UI, HTTP, login, database, file-system or platform-storage dependency.

## What is included

- **Post-Quantum Primitives:**
  - NIST FIPS 203 **ML-KEM-768** key encapsulation
  - NIST FIPS 204 **ML-DSA-65** digital signatures
  - AES-256-GCM authenticated content encryption
  - CSPRNG random generation with pre-allocated buffer security
- **Forward Secrecy & Post-Compromise Security:**
  - `PqcRatchetSession`: Continuous ML-KEM exchange and HKDF-SHA256 symmetric chain ratcheting (Signal/Double-Ratchet style)
- **High-Performance & Constant-Memory Streaming:**
  - `PqcV3ChunkedAttachmentCodec`: OOM-free streaming AEAD attachment encryption in fixed 64 KB memory windows for arbitrarily large files (gigabytes)
- **Scalable Group Messaging:**
  - `PqcGroupSenderKeyEngine`: $O(1)$ Sender-Key model for massive groups (10 to 10,000+ members) with one-time ML-KEM distribution and lightweight constant-size messages
- **Cryptographic Hardening & Defense-in-Depth:**
  - Memory zeroization (`secureZero`, `wipeBytes`) across all codec lifecycles
  - Timing side-channel attack protection (`constantTimeBytesEquals`, `constantTimeStringEquals`)
  - Strict **RFC 8785 Canonical JSON (JCS)** serialization (`canonicalJsonEncode`) for cross-platform deterministic signatures
- **Versioned Codecs & Protocols:**
  - PQCv2 private-message reader/writer and a read-only compatibility facade
  - Authenticated PQCv2 group-message reader/writer with legacy history decoding
  - Dedicated V2.5 writer profile (`releaseId: 2.5.0`)
  - Independent PQCv3 private/group recipient-wrap reader/writer
  - Transitional authenticated `group:v2-auth` group-message reader/writer
- **Key Vault, Recovery & Replay Protection:**
  - Atomic, checksummed key-vault orchestration over host storage adapters
  - Key continuity that retains rotated keys as historical decoders
  - Encrypted account-bound recovery with monotonic revision conflict checks
  - Automatic reinstall restore and key-missing decrypt retry
  - Health-gated writes and durable replay guard with sliding-window FIFO eviction

## Platform support

- Flutter Android / iOS / macOS / Windows / Linux
- Dart server and command-line applications
- Dart web (compiled to JavaScript and WebAssembly)

The SDK never chooses a platform persistence mechanism. A host application
must implement `PqcKeyRepository` or `PqcProductionAtomicStore` using Keychain/Keystore,
an encrypted database, IndexedDB, an HSM, or another appropriate facility.

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Application / Host Layer                        │
│       (Flutter App, CLI, Server Backend, Platform Keychain/Keystore)   │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────┐
│              PQC Secure Runtime & Key Management Layer                 │
│  - PqcSecureRuntime: Health-gated write boundary                       │
│  - PqcIntegrityKeyVault: Atomic, checksummed key retention             │
│  - PqcRecoveryCoordinator: Monotonic revision recovery                 │
│  - PqcReplayGuard: Deduplication & sliding-window collision defense    │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────┐
│               Advanced Cryptographic Engines & Codecs                  │
│  - PqcRatchetSession: Continuous Forward Secrecy & PCS (Ratchet)       │
│  - PqcV3ChunkedAttachmentCodec: Constant-RAM 64KB streaming AEAD       │
│  - PqcGroupSenderKeyEngine: O(1) Scalable Sender-Key group messaging   │
│  - PqcV3PrivateCodec / PqcV3GroupCodec: Recipient-wrap wire protocol   │
│  - PqcV2CompatibilityDecoder: Legacy frozen wire compatibility         │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────┐
│             Primitives, Zeroization & Canonical Security               │
│  - ML-KEM-768 (FIPS 203) & ML-DSA-65 (FIPS 204)                        │
│  - RFC 8785 Canonical JSON (JCS) serializer                            │
│  - Constant-time equality comparators & immediate buffer zeroization   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Practical Usage Guides

### 1. Forward Secrecy & Post-Compromise Security (`PqcRatchetSession`)

Use `PqcRatchetSession` when communication requires individual message-level
forward secrecy and break-in recovery:

```dart
import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';

final primitives = DartPqcPrimitiveSuite();
final aliceKeys = primitives.generateDeviceKeyset('alice-device');
final bobKeys = primitives.generateDeviceKeyset('bob-device');

// 1. Initial Handshake: Alice creates initiator session
final handshake = await PqcRatchetSession.createInitiator(
  conversationId: 42,
  localDevice: aliceKeys,
  remoteDevice: bobKeys.publicKey,
  primitives: primitives,
);
final aliceSession = handshake.session;

// 2. Bob creates responder session from Alice's handshake KEM ciphertext
final bobSession = await PqcRatchetSession.createResponder(
  conversationId: 42,
  localDevice: bobKeys,
  remoteDeviceId: aliceKeys.deviceId,
  initialKemCiphertextBase64: handshake.initialKemCiphertextBase64,
  primitives: primitives,
);

// 3. Alice encrypts Message #0 (ephemeral key is derived and wiped)
final payload = await aliceSession.encrypt(
  plaintext: 'Salom Bob! Kvant xavfsiz ratchet xabari.',
  remoteKemPublicKeyBase64: bobKeys.kemPublicKeyBase64,
);

// 4. Bob decrypts Message #0 and verifies Alice's ML-DSA-65 signature
final cleartext = await bobSession.decrypt(
  payload: payload,
  trustedRemoteSigningKeys: {aliceKeys.signingPublicKeyBase64},
);

print(cleartext); // "Salom Bob! Kvant xavfsiz ratchet xabari."

// 5. Clean up sensitive keys when closing session
aliceSession.dispose();
bobSession.dispose();
```

---

### 2. Large File Streaming without Out-Of-Memory (`PqcV3ChunkedAttachmentCodec`)

Encrypt attachments of arbitrary size (50 MB, 500 MB, 2 GB) with **fixed 64 KB RAM consumption**:

```dart
import 'dart:typed_data';
import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';

final codec = PqcV3ChunkedAttachmentCodec(primitives);
const conversation = PqcConversation(id: 42, type: 'private');

// 1. Create a signed manifest with per-device ML-KEM wraps
final manifestResult = await codec.createManifest(
  attachmentId: 'att-unique-uuid',
  conversation: conversation,
  filename: 'database_dump.zip',
  mimeType: 'application/zip',
  totalSizeBytes: totalFileLength,
  plaintextSha256: fileSha256Hex,
  sender: aliceKeys,
  recipientDevices: [bobKeys.publicKey],
  chunkSizeBytes: 64 * 1024, // 64 KB chunks
);

final manifest = manifestResult.manifest;
final contentKey = manifestResult.contentKey;

// 2. Encrypt chunks sequentially as they stream from disk/network
for (var index = 0; index < manifest.totalChunks; index++) {
  final chunkBytes = readNext64KbChunk();
  final encryptedChunk = await codec.encryptChunk(
    chunkPlaintext: chunkBytes,
    chunkIndex: index,
    attachmentId: manifest.attachmentId,
    contentKey: contentKey,
  );
  await uploadChunkToServer(encryptedChunk.bytes);
}

// 3. Recipient resolves content key from manifest
final recipientKey = await codec.resolveContentKey(
  manifest: manifest,
  localKeysets: [bobKeys],
  trustedSigningKeysByDevice: {aliceKeys.deviceId: {aliceKeys.signingPublicKeyBase64}},
);

// 4. Recipient decrypts and writes to disk chunk-by-chunk
final decryptedBytes = await codec.decryptChunk(
  chunk: downloadedChunk,
  attachmentId: manifest.attachmentId,
  contentKey: recipientKey,
);
```

---

### 3. Scalable $O(1)$ Group Messaging (`PqcGroupSenderKeyEngine`)

In groups with many members (100–10,000+), standard per-recipient KEM balloons payload size ($O(N)$).
`PqcGroupSenderKeyEngine` keeps message payload size constant ($O(1)$):

```dart
import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';

final groupEngine = PqcGroupSenderKeyEngine(primitives);
const conversationId = 999;
const epochId = 'epoch-2026-v1';

// 1. Setup: Sender creates and distributes Sender Key once to all active member devices
final distResult = await groupEngine.createDistribution(
  conversationId: conversationId,
  epochId: epochId,
  sender: aliceKeys,
  memberDevices: activeGroupMemberPublicKeys,
);
await broadcastToGroup(distResult.distribution.encode());

// 2. Each member receives the distribution and extracts their chain key
var memberChainKey = await groupEngine.receiveDistribution(
  distribution: PqcSenderKeyDistribution.decode(receivedDistributionPayload),
  localKeysets: [bobKeys],
  trustedSigningKeysByDevice: {aliceKeys.deviceId: {aliceKeys.signingPublicKeyBase64}},
);

// 3. Subsequent group messages are constant O(1) in size (~350 bytes + plaintext)
var senderChainKey = distResult.senderChainKey;

final sendResult = await groupEngine.encryptGroupMessage(
  conversationId: conversationId,
  epochId: epochId,
  sequenceNumber: 0,
  plaintext: 'Salom barchaga! Bu eng yengil va masshtabli guruh xabari.',
  sender: aliceKeys,
  currentChainKey: senderChainKey,
);
senderChainKey = sendResult.nextChainKey; // Step chain key forward (Forward Secrecy)

// 4. Any member decrypts the constant-size message with their chain key
final readResult = await groupEngine.decryptGroupMessage(
  payload: sendResult.payload,
  currentChainKey: memberChainKey,
  trustedSenderSigningKeys: {aliceKeys.signingPublicKeyBase64},
);
memberChainKey = readResult.nextChainKey;

print(readResult.plaintext);
```

---

### 4. Basic V3 Private Messaging (`PqcV3Engine`)

```dart
import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';

final bundle = PqcEngineBundles.v3(writerEnabled: true);
final manager = bundle.manager;
final v3 = bundle.writer as PqcV3Engine;

final payload = await v3.private.encrypt(
  conversation: const PqcConversation(id: 42, type: 'private'),
  messageId: 'msg-uuid-1',
  plaintext: 'Salom Bob',
  sender: aliceKeys,
  recipientDevices: [bobKeys.publicKey],
);

final result = await v3.decryptPrivate(
  conversation: const PqcConversation(id: 42, type: 'private'),
  payload: payload,
  localKeysets: [bobKeys],
  trustedSigningKeysByDevice: {aliceKeys.deviceId: {aliceKeys.signingPublicKeyBase64}},
);

if (result case PqcDecoded decoded) {
  print(decoded.plaintext);
}
```

---

## Secure Runtime & Production Key Storage

Production applications must implement `PqcProductionAtomicStore` with hardware-backed key protection:

```dart
final atomicStore = MyHardwareBackedAtomicStore(); // Implements PqcProductionAtomicStore
final vault = PqcIntegrityKeyVault(store: atomicStore);
final health = PqcCryptoHealthMonitor();

final recovery = PqcRecoveryCoordinator(
  vault: vault,
  transport: MyConditionalRecoveryTransport(),
  keyProvider: MyAccountRecoveryKeyProvider(),
  authorizer: MyFreshDeviceRecoveryAuthorizer(),
  healthMonitor: health,
);

final runtime = PqcSecureRuntime(
  manager: manager,
  vault: vault,
  recovery: recovery,
  replayGuard: PqcReplayGuard(PqcAtomicReplayStore(atomicStore)),
  healthMonitor: health,
);

await runtime.initializeAccount(accountId);
final writer = await runtime.prepareWriter(
  accountId: accountId,
  kind: PqcConversationKind.private,
  remote: serverCapabilities,
);
```

---

## Verification & Testing

Run the complete test suite and static analysis:

```sh
dart pub get
dart analyze
dart test
dart compile js tool/web_smoke.dart -O2 -o /tmp/pqc_engine_sdk.js
```

All 94 tests run against real FIPS-standardized ML-KEM, ML-DSA, and AES-256-GCM primitives.
