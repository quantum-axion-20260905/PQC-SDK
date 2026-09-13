# Security boundary

## Guarantees inside the SDK

- strict conversation id/type binding;
- sender-signature verification against host-supplied trust records;
- recipient device and keyset binding;
- authenticated content and attachment chunks;
- V3 per-recipient ML-KEM content-key wraps, including the sender device;
- V3 attachment file-key wraps with authenticated filename, MIME type and
  plaintext-size metadata;
- authenticated new `group:v2` and transitional `group:v2-auth` messages with
  ML-DSA sender signatures and AES-GCM context binding;
- V3 ML-DSA-65 signed envelope binding for conversation, message, sender and
  keyset metadata;
- historical private-key decoding;
- explicit missing-key, untrusted-sender, binding and corruption outcomes;
- no protocol fallback after a recognized payload fails authentication;
- remote capability checks before a writer is returned.
- strict recipient-wrap parsing that rejects malformed entries instead of
  silently dropping them;
- checksummed atomic key-vault records with compare-and-set retries;
- old-key retention and keyset/group-epoch rebinding rejection;
- account-bound authenticated recovery envelopes and revision conflicts;
- automatic key-missing restore/retry without protocol downgrade;
- V3 attachment key-missing recovery retry without retrying authentication
  failures;
- health-gated writes and durable replay/message-id collision claims.
- strict UTF-8 decoding for authenticated plaintext and persisted records;
- normalized storage/recovery adapter failures that preserve fail-closed health
  state.
- the default primitive suite always uses a cryptographically secure RNG;
  deterministic test randomness requires an explicit primitive-suite test
  double.

## Required host controls

Production hosts must implement `PqcProductionAtomicStore`. The SDK refuses to
construct a production vault unless the adapter declares encrypted-at-rest,
hardware-backed key protection and atomic durability. Ciphertext and its master
key must never share the same preferences/database namespace. Test-only memory
stores require the explicit `allowInsecureStoreForTesting` switch and that
switch is rejected in Dart product mode.

The host must protect the 32-byte recovery master key and implement a
conditional recovery transport. `PqcRecoveryCoordinator` additionally requires
a `PqcRecoveryAccessAuthorizer` which validates a fresh, device-bound,
short-lived proof for recovery reads and writes. A normal login token alone is
not sufficient. The recovery server receives only an authenticated encrypted
envelope, its revision and SHA-256 value.

Use `PqcAtomicReplayStore` with a durable adapter before presenting newly
received plaintext. Duplicate ciphertext is classified separately from reuse
of the same message id for different ciphertext.

Never log plaintext, private keys, shared secrets, attachment descriptors or
full encrypted recovery blobs. Error telemetry should contain only a stable
error category and non-secret correlation id.

For every new V2 group write, require the sender keyset and advertise
`PqcV2Wire.groupAlgorithm` in the remote `groupAlgorithms` capability. New
`group:v2` payloads include an ML-DSA sender signature and bind conversation,
epoch and sender metadata into AES-GCM. The transitional `group:v2-auth`
prefix remains readable for payloads emitted by the previous release. The old
unauthenticated `group:v2` algorithm is decode-only history and is never
emitted by the current writer.

Before encrypted writes, hosts must complete account initialization and keep the
runtime and recovery coordinator attached to the same health monitor. Device
ids must not contain the key-vault keyset-id delimiter |; V2 group-wrap device
ids must additionally not contain :. Inbound replay claims must use the same
initialized account session; decrypting history alone never clears a missing
current-key write block.

## Cryptographic changes

V2 private serialization, group wrapping and attachments remain compatible
with their released contracts. The V2 group message write algorithm was
explicitly advanced for the production transition: current writers emit the
authenticated algorithm, while the previous unauthenticated algorithm is
accepted only for history. V3 retains its separately versioned envelope and
attachment cipher. Any future prefix, algorithm, field-order, signing-context,
HKDF or nonce change requires a new engine version and decoder.

Security reports: contact the repository owner through a private channel. Do
not open a public issue containing keys or production payloads.
