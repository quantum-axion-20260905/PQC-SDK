# Security boundary

## Guarantees inside the SDK

- strict conversation id/type binding;
- sender-signature verification against host-supplied trust records;
- recipient device and keyset binding;
- authenticated content and attachment chunks;
- V3 per-recipient ML-KEM content-key wraps, including the sender device;
- V3 attachment file-key wraps with authenticated filename, MIME type and
  plaintext-size metadata;
- authenticated `group:v2-auth` messages with ML-DSA sender signatures and
  AES-GCM context binding;
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

For new V2 group writes, advertise and require
`PqcV2Wire.authenticatedGroupPrefix` (`group:v2-auth`) on every participant,
then use `PqcV2AuthenticatedGroupCodec`. The frozen `group:v2` format remains
available only for compatibility/history and does not gain sender or metadata
authentication retroactively.

Before encrypted writes, hosts must complete account initialization and keep the
runtime and recovery coordinator attached to the same health monitor. Device
ids must not contain the key-vault keyset-id delimiter |; V2 group-wrap device
ids must additionally not contain :. Inbound replay claims must use the same
initialized account session; decrypting history alone never clears a missing
current-key write block.

## Cryptographic changes

PQCv2 constants and serialization are frozen. V3 has a separately versioned
envelope and attachment cipher. Changing a prefix, algorithm label, field,
field order, signing context, HKDF input or nonce derivation requires a new
engine version and decoder. Never silently mutate a released wire format.

The frozen V2 group message format authenticates ciphertext with the shared
group epoch key but does not identify the individual sender or bind envelope
metadata as AEAD associated data. The negotiated `group:v2-auth` subformat
closes those gaps for new messages without changing frozen `group:v2` history.

Security reports: contact the repository owner through a private channel. Do
not open a public issue containing keys or production payloads.
