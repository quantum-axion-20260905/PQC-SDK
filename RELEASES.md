# Engine release map

This file is the operational source of truth for selecting a protocol release.
Do not change a released wire contract in place.

| SDK release profile | Active writer | Read-only history decoders | Wire format |
| --- | --- | --- | --- |
| `PqcReleaseProfiles.v2` | `PqcV2Engine` | `PqcV2Engine` | `pqc:v2`, `group:v2`, `attachment:v2` |
| `PqcReleaseProfiles.v25` | `PqcV25Writer` | `PqcV2CompatibilityDecoder` | `pqc:v2`, `group:v2`, `attachment:v2` |
| `PqcReleaseProfiles.v3` | `PqcV3Engine` | `PqcV2CompatibilityDecoder`, `PqcV3Engine` | `pqc:v3`, `group:v3`, `attachment:v3` |

Always construct profiles with `PqcEngineBundles.v2()`,
`PqcEngineBundles.v25()` or `PqcEngineBundles.v3()`. All writers are closed
by default. A host opens a
writer only after its storage health, encrypted recovery synchronization and
remote capability checks succeed.

V2 and V2.5 group writers emit `PqcV2Wire.groupAlgorithm` and require that
exact identifier in `PqcRemoteCapabilities.groupAlgorithms`. The previous
unauthenticated `PqcV2Wire.legacyGroupAlgorithm` is retained only for history
decoding; advertising the shared `group:v2` prefix alone is insufficient for
write compatibility.

## Immutable history rule

When a future engine is released:

1. add its new writer and decoder under a new prefix and wire version;
2. retain every older decoder required for supported history;
3. never put an older writer in the new bundle;
4. use a new release tag rather than changing an existing tag.

Keychain/Keystore/IndexedDB, recovery authorization, server capability records
and group membership data remain host adapters. They are intentionally outside
the pure-Dart SDK and must be provided by every integrating app.
