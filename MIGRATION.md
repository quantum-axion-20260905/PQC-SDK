# Application migration

The package is wired into the Flutter application only through the dedicated
adapter package. UI, HTTP and platform storage do not enter the engine SDK.

## Recommended sequence

1. Add the package by an immutable Git tag.
2. Implement `PqcKeyRepository` over the application's secure storage.
3. Import the current keyset and every historical V2/V3 keyset without changing
   bytes or keyset ids.
4. Build the trusted signing-key map from current and historical device
   records.
5. Run the SDK as a read-only shadow decoder and compare results with the
   currently deployed production decoder.
6. Exercise reinstall, relogin, account switch, key rotation, device revoke
   and group rekey recovery tests.
7. Enable the selected writer only after the server advertises all required
   prefixes and exact algorithm identifiers. V2/V2.5 writes require
   `pqc:v2`/`group:v2`, `PqcV2Wire.privateAlgorithm` and
   `PqcV2Wire.groupAlgorithm`; the old unauthenticated group algorithm is
   decode-only history. V3 requires `pqc:v3`/`group:v3`, its private/group
   algorithms and `attachment:v3`.
8. Roll back by closing the writer gate; keep the decoder registered.

The secure runtime is session-scoped: call initializeAccount after login and
before inbound replay claims, any writer, rotation, revocation or group-epoch
persistence operation.
If recovery initialization fails, the runtime remains closed for writes until
the account is initialized successfully again.

For V3 groups, obtain the complete current member-device list from the host's
membership service and pass it as `expectedMemberDevices`. The SDK validates
that every intended device receives a signed recipient wrap before encryption.
After a membership change, write a new V3 group payload with the new device
set; old payloads remain decryptable only for devices that were covered by
their historical envelope.

## Adapter boundaries

- API models -> `PqcDevicePublicKey`
- secure store -> `PqcKeyRepository`
- recovery endpoint -> `PqcRecoveryRepository`
- chat model -> `PqcConversation`
- backend capability response -> `PqcRemoteCapabilities`

The SDK never migrates V2 keys into new cryptographic bytes. V3 owns an
independent writer/decoder and retains the V2 compatibility decoder as a
strictly read-only component. A V3 authentication failure is not tried with a
V2 decoder.
