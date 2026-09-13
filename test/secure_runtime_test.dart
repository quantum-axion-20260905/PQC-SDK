import 'dart:convert';

import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';
import 'package:test/test.dart';

class _FixedRecoveryKeyProvider implements PqcRecoveryKeyProvider {
  const _FixedRecoveryKeyProvider(this.seed);

  final int seed;

  @override
  Future<List<int>> recoveryKey(String accountId) async =>
      List<int>.generate(32, (index) => (seed + index) & 0xff);
}

class _InterruptingAtomicStore implements PqcAtomicStore {
  _InterruptingAtomicStore(this.delegate);

  final PqcMemoryAtomicStore delegate;
  bool interruptNextWrite = false;

  @override
  Future<PqcAtomicRecord?> read({
    required String namespace,
    required String key,
  }) => delegate.read(namespace: namespace, key: key);

  @override
  Future<bool> compareAndSet({
    required String namespace,
    required String key,
    required int? expectedRevision,
    required PqcAtomicRecord value,
  }) async {
    if (interruptNextWrite) {
      interruptNextWrite = false;
      throw StateError('simulated power loss before atomic commit');
    }
    return delegate.compareAndSet(
      namespace: namespace,
      key: key,
      expectedRevision: expectedRevision,
      value: value,
    );
  }
}

class _ProductionAtomicStore implements PqcProductionAtomicStore {
  final PqcMemoryAtomicStore _delegate = PqcMemoryAtomicStore();

  @override
  bool get encryptedAtRest => true;

  @override
  bool get hardwareBackedKeyProtection => true;

  @override
  bool get atomicDurability => true;

  @override
  Future<PqcAtomicRecord?> read({
    required String namespace,
    required String key,
  }) => _delegate.read(namespace: namespace, key: key);

  @override
  Future<bool> compareAndSet({
    required String namespace,
    required String key,
    required int? expectedRevision,
    required PqcAtomicRecord value,
  }) => _delegate.compareAndSet(
    namespace: namespace,
    key: key,
    expectedRevision: expectedRevision,
    value: value,
  );
}

class _RecordingRecoveryAuthorizer implements PqcRecoveryAccessAuthorizer {
  final List<PqcRecoveryOperation> operations = [];

  @override
  Future<void> authorize({
    required String accountId,
    required PqcRecoveryOperation operation,
  }) async {
    operations.add(operation);
  }
}

class _ThrowingRecoveryAuthorizer implements PqcRecoveryAccessAuthorizer {
  @override
  Future<void> authorize({
    required String accountId,
    required PqcRecoveryOperation operation,
  }) async {
    throw StateError('authorization service offline');
  }
}

class _ThrowingRecoveryTransport implements PqcRecoveryRepository {
  @override
  Future<PqcRecoverySnapshot?> downloadLatestEncryptedSnapshot(
    String accountId,
  ) async {
    throw StateError('recovery service offline');
  }

  @override
  Future<void> uploadEncryptedSnapshot({
    required String accountId,
    required int revision,
    required List<int> encryptedBlob,
    required String sha256,
  }) async {
    throw StateError('recovery service offline');
  }
}

class _ConflictingRecoveryTransport
    implements PqcConditionalRecoveryRepository {
  @override
  Future<PqcRecoverySnapshot?> downloadLatestEncryptedSnapshot(
    String accountId,
  ) async => null;

  @override
  Future<void> uploadEncryptedSnapshot({
    required String accountId,
    required int revision,
    required List<int> encryptedBlob,
    required String sha256,
  }) async {}

  @override
  Future<bool> uploadIfCurrentRevision({
    required String accountId,
    required int? expectedCurrentRevision,
    required int revision,
    required List<int> encryptedBlob,
    required String sha256,
  }) async => false;
}

void main() {
  const accountId = 'account-1';
  const privateConversation = PqcConversation(id: 7, type: 'private');
  const groupConversation = PqcConversation(id: 8, type: 'group');
  const capabilities = PqcRemoteCapabilities(
    privateReadPrefixes: {PqcV2Wire.privatePrefix},
    groupReadPrefixes: {PqcV2Wire.groupPrefix},
    privateWritePrefixes: {PqcV2Wire.privatePrefix},
    groupWritePrefixes: {PqcV2Wire.groupPrefix},
    privateAlgorithms: {PqcV2Wire.privateAlgorithm},
    groupAlgorithms: {PqcV2Wire.groupAlgorithm},
    attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
    minimumDecoderVersion: 2,
  );

  late PqcV2Engine engine;

  setUp(() {
    engine = PqcV2Engine();
  });

  test('production vault rejects unprotected storage by default', () {
    expect(
      () => PqcIntegrityKeyVault(store: PqcMemoryAtomicStore()),
      throwsA(
        isA<PqcVaultException>().having(
          (error) => error.failure,
          'failure',
          PqcVaultFailure.unavailable,
        ),
      ),
    );
    expect(
      () => PqcIntegrityKeyVault(store: _ProductionAtomicStore()),
      returnsNormally,
    );
  });

  test('recovery refuses to start without device-bound authorization', () {
    final vault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    expect(
      () => PqcRecoveryCoordinator(
        vault: vault,
        transport: PqcMemoryRecoveryRepository(),
        keyProvider: const _FixedRecoveryKeyProvider(1),
      ),
      throwsA(
        isA<PqcRecoveryException>().having(
          (error) => error.failure,
          'failure',
          PqcRecoveryFailure.authorizationRequired,
        ),
      ),
    );
  });

  test(
    'secure runtime refuses encrypted writes before account initialization',
    () async {
      final store = PqcMemoryAtomicStore();
      final health = PqcCryptoHealthMonitor();
      final vault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: store,
      );
      final recovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: vault,
        transport: PqcMemoryRecoveryRepository(),
        keyProvider: const _FixedRecoveryKeyProvider(3),
        healthMonitor: health,
      );
      final writer = PqcV25Writer();
      final runtime = PqcSecureRuntime(
        manager: PqcEngineManager(
          decoders: [engine],
          activeWriter: writer,
          writerEnabled: true,
          releaseProfile: PqcReleaseProfiles.v25,
        ),
        vault: vault,
        recovery: recovery,
        replayGuard: PqcReplayGuard(PqcMemoryReplayStore()),
        healthMonitor: health,
      );

      expect(
        () => runtime.requireWriter(
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        throwsA(isA<PqcSecureRuntimeException>()),
      );
      await expectLater(
        runtime.prepareWriter(
          accountId: accountId,
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        throwsA(isA<PqcSecureRuntimeException>()),
      );
      await expectLater(
        runtime.acceptInbound(
          accountId: accountId,
          conversationId: privateConversation.id,
          messageId: 'before-init',
          encryptedPayload: 'ciphertext',
        ),
        throwsA(isA<PqcSecureRuntimeException>()),
      );
      await expectLater(
        runtime.decryptRetry.decryptPrivate(
          accountId: accountId,
          conversation: privateConversation,
          payload: '',
          trustedSigningKeysByDevice: const {},
        ),
        throwsA(isA<PqcSecureRuntimeException>()),
      );

      await runtime.initializeAccount(accountId);
      await runtime.rotateDeviceKeyset(
        accountId: accountId,
        deviceId: 'initialized-phone',
      );
      expect(
        await runtime.prepareWriter(
          accountId: accountId,
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        same(writer),
      );
      expect(
        await runtime.acceptInbound(
          accountId: accountId,
          conversationId: privateConversation.id,
          messageId: 'after-init',
          encryptedPayload: 'ciphertext',
        ),
        PqcReplayDecision.accepted,
      );
    },
  );

  test(
    'recovery normalizes authorization and transport adapter failures',
    () async {
      final vault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final keyProvider = const _FixedRecoveryKeyProvider(7);

      final authorizationFailure = PqcRecoveryCoordinator(
        vault: vault,
        transport: PqcMemoryRecoveryRepository(),
        keyProvider: keyProvider,
        authorizer: _ThrowingRecoveryAuthorizer(),
      );
      await expectLater(
        authorizationFailure.restoreLatest(accountId),
        throwsA(
          isA<PqcRecoveryException>().having(
            (error) => error.failure,
            'failure',
            PqcRecoveryFailure.authorizationRequired,
          ),
        ),
      );

      final transportFailure = PqcRecoveryCoordinator(
        vault: vault,
        transport: _ThrowingRecoveryTransport(),
        keyProvider: keyProvider,
        allowUnauthenticatedRecoveryForTesting: true,
      );
      await expectLater(
        transportFailure.restoreLatest(accountId),
        throwsA(
          isA<PqcRecoveryException>().having(
            (error) => error.failure,
            'failure',
            PqcRecoveryFailure.unavailable,
          ),
        ),
      );
    },
  );

  test('history-only recovery keeps current-key writes blocked', () async {
    final transport = PqcMemoryRecoveryRepository();
    const keyProvider = _FixedRecoveryKeyProvider(13);
    final sourceVault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    final sourceRecovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: sourceVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    final historical = engine.generateDeviceKeyset('history-only-phone');
    await sourceVault.saveDeviceKeyset(
      accountId: accountId,
      keyset: historical,
      makeCurrent: true,
    );
    await sourceRecovery.synchronize(accountId);
    await sourceVault.revokeCurrentDeviceKeyset(
      accountId: accountId,
      deviceId: historical.deviceId,
    );
    await sourceRecovery.synchronize(accountId);

    final sender = engine.generateDeviceKeyset('history-only-sender');
    final payload = await engine.private.encrypt(
      conversation: privateConversation,
      plaintext: 'history-only message',
      sender: sender,
      recipientDevices: [historical.publicKey],
    );
    final health = PqcCryptoHealthMonitor();
    final targetVault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    final targetRecovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: targetVault,
      transport: transport,
      keyProvider: keyProvider,
      healthMonitor: health,
    );
    final retry = PqcDecryptRetryCoordinator(
      manager: PqcEngineManager(decoders: [engine]),
      vault: targetVault,
      recovery: targetRecovery,
      healthMonitor: health,
    );

    final result = await retry.decryptPrivate(
      accountId: accountId,
      conversation: privateConversation,
      payload: payload,
      trustedSigningKeysByDevice: {
        sender.deviceId: {sender.signingPublicKeyBase64},
      },
    );
    expect((result as PqcDecoded).plaintext, 'history-only message');
    expect(
      health.snapshot.blockingIssues,
      contains(PqcHealthIssue.currentKeyMissing),
    );
    expect(await targetVault.readCurrentDeviceKeyset(accountId), isNull);
  });

  test('vault rejects an invalid compare-and-set retry budget', () {
    expect(
      () => PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
        maxCompareAndSetAttempts: 0,
      ),
      throwsArgumentError,
    );
  });

  test('vault rejects a persisted zero-revision record', () async {
    final store = PqcMemoryAtomicStore();
    final accountBinding = pqcAccountBinding(accountId);
    await store.compareAndSet(
      namespace: PqcIntegrityKeyVault.storageNamespace,
      key: accountBinding,
      expectedRevision: null,
      value: PqcAtomicRecord(revision: 0, bytes: [1], sha256: ''),
    );
    final vault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: store,
    );

    await expectLater(
      vault.verifyIntegrity(accountId),
      throwsA(
        isA<PqcVaultException>().having(
          (error) => error.failure,
          'failure',
          PqcVaultFailure.corrupted,
        ),
      ),
    );
  });

  test('recovery snapshots reject malformed collection entries', () {
    expect(
      () => PqcKeyVaultSnapshot.fromJson({
        'schema_version': PqcKeyVaultSnapshot.currentSchemaVersion,
        'account_binding': pqcAccountBinding(accountId),
        'revision': 0,
        'current_device_keyset': null,
        'historical_device_keysets': const <Object?>[42],
        'group_epochs': const <Object?>[],
      }),
      throwsA(isA<FormatException>()),
    );
  });

  test('secure runtime rejects split health-monitor wiring', () {
    final vault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    final recovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: vault,
      transport: PqcMemoryRecoveryRepository(),
      keyProvider: const _FixedRecoveryKeyProvider(4),
    );

    expect(
      () => PqcSecureRuntime(
        manager: PqcEngineManager(decoders: [engine]),
        vault: vault,
        recovery: recovery,
        replayGuard: PqcReplayGuard(PqcMemoryReplayStore()),
        healthMonitor: PqcCryptoHealthMonitor(),
      ),
      throwsArgumentError,
    );
  });

  test('authorized recovery checks every read and write operation', () async {
    final vault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    final authorizer = _RecordingRecoveryAuthorizer();
    final recovery = PqcRecoveryCoordinator(
      vault: vault,
      transport: PqcMemoryRecoveryRepository(),
      keyProvider: const _FixedRecoveryKeyProvider(2),
      authorizer: authorizer,
    );
    await vault.saveDeviceKeyset(
      accountId: accountId,
      keyset: engine.generateDeviceKeyset('authorized-device'),
      makeCurrent: true,
    );
    await recovery.synchronize(accountId);
    expect(
      authorizer.operations,
      containsAll(<PqcRecoveryOperation>[
        PqcRecoveryOperation.read,
        PqcRecoveryOperation.write,
      ]),
    );
  });

  test(
    'restoring a snapshot without a current key keeps writes blocked',
    () async {
      final transport = PqcMemoryRecoveryRepository();
      const keyProvider = _FixedRecoveryKeyProvider(5);
      final sourceVault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final sourceRecovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: sourceVault,
        transport: transport,
        keyProvider: keyProvider,
      );
      await sourceVault.saveGroupEpoch(
        accountId: accountId,
        conversationId: groupConversation.id,
        epoch: PqcGroupEpoch(
          epochId: 'group-only-epoch',
          secretKeyBytes: List<int>.filled(32, 5),
        ),
      );
      await sourceRecovery.synchronize(accountId);

      final targetVault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final health = PqcCryptoHealthMonitor();
      final targetRecovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: targetVault,
        transport: transport,
        keyProvider: keyProvider,
        healthMonitor: health,
      );

      expect(await targetRecovery.restoreLatest(accountId), isTrue);
      expect(
        health.snapshot.blockingIssues,
        contains(PqcHealthIssue.currentKeyMissing),
      );
    },
  );

  test('V2.5 release uses authenticated V2 wire and retains its decoder', () {
    final writer = PqcV25Writer();
    final manager = PqcEngineManager(
      decoders: [engine],
      activeWriter: writer,
      writerEnabled: true,
      releaseProfile: PqcReleaseProfiles.v25,
    );

    expect(manager.releaseId, '2.5.0');
    expect(manager.wireProtocolId, 'v2');
    expect(manager.decoders, [same(engine)]);
    expect(manager.activeWriter, same(writer));
    expect(manager.activeWriter, isNot(same(engine)));
    expect(manager.activeWriter?.protocolVersion, 2);
    expect(
      manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: capabilities,
      ),
      same(writer),
    );
  });

  test('V2.5 refuses a frozen decoder reused as its active writer', () {
    expect(
      () => PqcEngineManager(
        decoders: [engine],
        activeWriter: engine,
        writerEnabled: true,
        releaseProfile: PqcReleaseProfiles.v25,
      ),
      throwsArgumentError,
    );
  });

  test(
    'atomic rotation preserves every old keyset as read-only history',
    () async {
      final vault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final first = engine.generateDeviceKeyset('phone');
      final second = engine.generateDeviceKeyset('phone');
      final third = engine.generateDeviceKeyset('phone');

      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: first,
        makeCurrent: true,
      );
      await Future.wait([
        vault.saveDeviceKeyset(
          accountId: accountId,
          keyset: second,
          makeCurrent: true,
        ),
        vault.saveDeviceKeyset(
          accountId: accountId,
          keyset: third,
          makeCurrent: true,
        ),
      ]);

      final current = await vault.readCurrentDeviceKeyset(accountId);
      final history = await vault.readHistoricalDeviceKeysets(accountId);
      expect(
        {current!.keysetId, ...history.map((item) => item.keysetId)},
        {first.keysetId, second.keysetId, third.keysetId},
      );
      expect(history, hasLength(2));
    },
  );

  test(
    'power loss before atomic commit leaves the previous vault valid',
    () async {
      final memory = PqcMemoryAtomicStore();
      final store = _InterruptingAtomicStore(memory);
      final vault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: store,
      );
      final first = engine.generateDeviceKeyset('phone');
      final second = engine.generateDeviceKeyset('phone');
      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: first,
        makeCurrent: true,
      );

      store.interruptNextWrite = true;
      await expectLater(
        vault.saveDeviceKeyset(
          accountId: accountId,
          keyset: second,
          makeCurrent: true,
        ),
        throwsA(
          isA<PqcVaultException>().having(
            (error) => error.failure,
            'failure',
            PqcVaultFailure.unavailable,
          ),
        ),
      );

      expect(
        (await vault.readCurrentDeviceKeyset(accountId))?.keysetId,
        first.keysetId,
      );
      await vault.verifyIntegrity(accountId);
    },
  );

  test('chaos writes expose either the old or fully committed vault', () async {
    final memory = PqcMemoryAtomicStore();
    final store = _InterruptingAtomicStore(memory);
    final vault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: store,
    );
    final candidates = List.generate(
      4,
      (index) => engine.generateDeviceKeyset('chaos-phone-$index'),
    );
    final committed = <String>{};

    for (var iteration = 0; iteration < 24; iteration++) {
      final candidate = candidates[iteration % candidates.length];
      store.interruptNextWrite = iteration % 3 == 1;
      try {
        await vault.saveDeviceKeyset(
          accountId: accountId,
          keyset: candidate,
          makeCurrent: true,
        );
        committed.add(candidate.keysetId);
      } on PqcVaultException catch (error) {
        // Simulated crash happened before the atomic commit.
        expect(error.failure, PqcVaultFailure.unavailable);
      }
      await vault.verifyIntegrity(accountId);
      final snapshot = await vault.exportSnapshot(accountId);
      final persisted = {
        if (snapshot.currentDeviceKeyset case final current?) current.keysetId,
        ...snapshot.historicalDeviceKeysets.map((item) => item.keysetId),
      };
      expect(persisted, committed);
    }
  });

  test('checksum corruption and keyset rebinding fail closed', () async {
    final memory = PqcMemoryAtomicStore();
    final vault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: memory,
    );
    final keyset = engine.generateDeviceKeyset('phone');
    await vault.saveDeviceKeyset(
      accountId: accountId,
      keyset: keyset,
      makeCurrent: true,
    );
    final conflicting = PqcDeviceKeyset(
      deviceId: keyset.deviceId,
      kemPublicKeyBase64: keyset.kemPublicKeyBase64,
      kemSecretKeyBase64: base64Encode(List<int>.filled(2400, 9)),
      signingPublicKeyBase64: keyset.signingPublicKeyBase64,
      signingSecretKeyBase64: keyset.signingSecretKeyBase64,
    );
    await expectLater(
      vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: conflicting,
        makeCurrent: true,
      ),
      throwsA(
        isA<PqcVaultException>().having(
          (error) => error.failure,
          'failure',
          PqcVaultFailure.continuityViolation,
        ),
      ),
    );

    memory.corruptForTest(
      namespace: PqcIntegrityKeyVault.storageNamespace,
      key: pqcAccountBinding(accountId),
    );
    await expectLater(
      vault.verifyIntegrity(accountId),
      throwsA(
        isA<PqcVaultException>().having(
          (error) => error.failure,
          'failure',
          PqcVaultFailure.corrupted,
        ),
      ),
    );
  });

  test(
    'encrypted recovery restores reinstall and retries private decrypt',
    () async {
      final transport = PqcMemoryRecoveryRepository();
      const keyProvider = _FixedRecoveryKeyProvider(17);
      final sourceVault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final sourceRecovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: sourceVault,
        transport: transport,
        keyProvider: keyProvider,
      );
      final recipient = engine.generateDeviceKeyset('recipient-phone');
      final sender = engine.generateDeviceKeyset('sender-phone');
      await sourceVault.saveDeviceKeyset(
        accountId: accountId,
        keyset: recipient,
        makeCurrent: true,
      );
      await sourceRecovery.synchronize(accountId);
      final payload = await engine.private.encrypt(
        conversation: privateConversation,
        plaintext: 'reinstall survived',
        sender: sender,
        recipientDevices: [recipient.publicKey],
      );

      final reinstalledVault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final health = PqcCryptoHealthMonitor();
      final reinstalledRecovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: reinstalledVault,
        transport: transport,
        keyProvider: keyProvider,
        healthMonitor: health,
      );
      final retry = PqcDecryptRetryCoordinator(
        manager: PqcEngineManager(decoders: [engine]),
        vault: reinstalledVault,
        recovery: reinstalledRecovery,
        healthMonitor: health,
      );
      final result = await retry.decryptPrivate(
        accountId: accountId,
        conversation: privateConversation,
        payload: payload,
        trustedSigningKeysByDevice: {
          sender.deviceId: {sender.signingPublicKeyBase64},
        },
      );

      expect(result, isA<PqcDecoded>());
      expect((result as PqcDecoded).plaintext, 'reinstall survived');
      expect(
        (await reinstalledVault.readCurrentDeviceKeyset(accountId))?.keysetId,
        recipient.keysetId,
      );
    },
  );

  test(
    'account scopes never leak keys across relogin or account switch',
    () async {
      final vault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final first = engine.generateDeviceKeyset('phone');
      final rotated = engine.generateDeviceKeyset('phone');
      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: first,
        makeCurrent: true,
      );
      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: rotated,
        makeCurrent: true,
      );

      expect(
        (await vault.readCurrentDeviceKeyset(accountId))?.keysetId,
        rotated.keysetId,
      );
      expect(
        (await vault.readHistoricalDeviceKeysets(
          accountId,
        )).map((item) => item.keysetId),
        contains(first.keysetId),
      );
      expect(await vault.readCurrentDeviceKeyset('another-account'), isNull);
      expect(
        await vault.readHistoricalDeviceKeysets('another-account'),
        isEmpty,
      );
      expect(
        (await vault.readCurrentDeviceKeyset(accountId))?.keysetId,
        rotated.keysetId,
      );
    },
  );

  test('relogin is idempotent and keeps the same current key', () async {
    final store = PqcMemoryAtomicStore();
    final transport = PqcMemoryRecoveryRepository();
    final vault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: store,
    );
    final health = PqcCryptoHealthMonitor();
    final recovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: vault,
      transport: transport,
      keyProvider: const _FixedRecoveryKeyProvider(19),
      healthMonitor: health,
    );
    final runtime = PqcSecureRuntime(
      manager: PqcEngineManager(
        decoders: [engine],
        activeWriter: PqcV25Writer(),
        writerEnabled: true,
        releaseProfile: PqcReleaseProfiles.v25,
      ),
      vault: vault,
      recovery: recovery,
      replayGuard: PqcReplayGuard(PqcAtomicReplayStore(store)),
      healthMonitor: health,
    );
    await runtime.initializeAccount(accountId);
    final created = await runtime.rotateDeviceKeyset(
      accountId: accountId,
      deviceId: 'phone',
    );
    await runtime.initializeAccount(accountId);
    await runtime.initializeAccount(accountId);

    expect(
      (await vault.readCurrentDeviceKeyset(accountId))?.keysetId,
      created.keysetId,
    );
    expect(await vault.readHistoricalDeviceKeysets(accountId), isEmpty);
    expect(health.snapshot.isSafeToWrite, isTrue);
  });

  test('account switch resets account-scoped health blockers', () async {
    final store = PqcMemoryAtomicStore();
    final vault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: store,
    );
    final health = PqcCryptoHealthMonitor();
    final recovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: vault,
      transport: PqcMemoryRecoveryRepository(),
      keyProvider: const _FixedRecoveryKeyProvider(23),
      healthMonitor: health,
    );
    final runtime = PqcSecureRuntime(
      manager: PqcEngineManager(decoders: [engine]),
      vault: vault,
      recovery: recovery,
      replayGuard: PqcReplayGuard(PqcAtomicReplayStore(store)),
      healthMonitor: health,
    );
    await vault.saveDeviceKeyset(
      accountId: accountId,
      keyset: engine.generateDeviceKeyset('account-one-phone'),
      makeCurrent: true,
    );
    await vault.saveDeviceKeyset(
      accountId: 'account-two',
      keyset: engine.generateDeviceKeyset('account-two-phone'),
      makeCurrent: true,
    );
    await runtime.initializeAccount(accountId);
    health.report(PqcHealthIssue.currentKeyMissing, blocking: true);
    health.report(PqcHealthIssue.continuityViolation, blocking: true);
    health.report(PqcHealthIssue.recoveryUnavailable, blocking: true);
    health.report(PqcHealthIssue.recoveryConflict, blocking: true);
    health.report(PqcHealthIssue.replayDetected, blocking: true);
    expect(health.snapshot.isSafeToWrite, isFalse);

    await runtime.initializeAccount('account-two');

    expect(health.snapshot.isSafeToWrite, isTrue);
  });

  test(
    'parallel account initialization leaves the last session active',
    () async {
      final store = PqcMemoryAtomicStore();
      final vault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: store,
      );
      final health = PqcCryptoHealthMonitor();
      final recovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: vault,
        transport: PqcMemoryRecoveryRepository(),
        keyProvider: const _FixedRecoveryKeyProvider(29),
        healthMonitor: health,
      );
      final writer = PqcV25Writer();
      final runtime = PqcSecureRuntime(
        manager: PqcEngineManager(
          decoders: [engine],
          activeWriter: writer,
          writerEnabled: true,
          releaseProfile: PqcReleaseProfiles.v25,
        ),
        vault: vault,
        recovery: recovery,
        replayGuard: PqcReplayGuard(PqcMemoryReplayStore()),
        healthMonitor: health,
      );
      await vault.saveDeviceKeyset(
        accountId: 'parallel-one',
        keyset: engine.generateDeviceKeyset('parallel-one-phone'),
        makeCurrent: true,
      );
      await vault.saveDeviceKeyset(
        accountId: 'parallel-two',
        keyset: engine.generateDeviceKeyset('parallel-two-phone'),
        makeCurrent: true,
      );

      await Future.wait([
        runtime.initializeAccount('parallel-one'),
        runtime.initializeAccount('parallel-two'),
      ]);

      await expectLater(
        runtime.prepareWriter(
          accountId: 'parallel-one',
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        throwsA(isA<PqcSecureRuntimeException>()),
      );
      await runtime.prepareWriter(
        accountId: 'parallel-two',
        kind: PqcConversationKind.private,
        remote: capabilities,
      );
    },
  );

  test(
    'device revoke preserves decrypt history and blocks writes until rotation',
    () async {
      final store = PqcMemoryAtomicStore();
      final transport = PqcMemoryRecoveryRepository();
      final vault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: store,
      );
      final health = PqcCryptoHealthMonitor();
      final recovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: vault,
        transport: transport,
        keyProvider: const _FixedRecoveryKeyProvider(23),
        healthMonitor: health,
      );
      final writer = PqcV25Writer();
      final runtime = PqcSecureRuntime(
        manager: PqcEngineManager(
          decoders: [engine],
          activeWriter: writer,
          writerEnabled: true,
          releaseProfile: PqcReleaseProfiles.v25,
        ),
        vault: vault,
        recovery: recovery,
        replayGuard: PqcReplayGuard(PqcAtomicReplayStore(store)),
        healthMonitor: health,
      );
      await runtime.initializeAccount(accountId);
      final original = await runtime.rotateDeviceKeyset(
        accountId: accountId,
        deviceId: 'phone',
      );
      final sender = engine.generateDeviceKeyset('sender');
      final payload = await writer.private.encrypt(
        conversation: privateConversation,
        plaintext: 'retained after revoke',
        sender: sender,
        recipientDevices: [original.publicKey],
      );

      await runtime.revokeCurrentDevice(
        accountId: accountId,
        deviceId: 'phone',
      );
      expect(await vault.readCurrentDeviceKeyset(accountId), isNull);
      expect(
        (await vault.readHistoricalDeviceKeysets(accountId)).single.keysetId,
        original.keysetId,
      );
      expect(
        () => runtime.requireWriter(
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        throwsA(isA<PqcCryptoHealthException>()),
      );

      final decoded = await runtime.decryptRetry.decryptPrivate(
        accountId: accountId,
        conversation: privateConversation,
        payload: payload,
        trustedSigningKeysByDevice: {
          sender.deviceId: {sender.signingPublicKeyBase64},
        },
      );
      expect((decoded as PqcDecoded).plaintext, 'retained after revoke');

      final replacement = await runtime.rotateDeviceKeyset(
        accountId: accountId,
        deviceId: 'replacement-phone',
      );
      expect(replacement.keysetId, isNot(original.keysetId));
      expect(
        (await vault.readHistoricalDeviceKeysets(
          accountId,
        )).map((item) => item.keysetId),
        contains(original.keysetId),
      );
      expect(health.snapshot.isSafeToWrite, isTrue);
    },
  );

  test('encrypted recovery restores group epoch before retry', () async {
    final transport = PqcMemoryRecoveryRepository();
    const keyProvider = _FixedRecoveryKeyProvider(21);
    final sourceVault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    final sourceRecovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: sourceVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    final device = engine.generateDeviceKeyset('phone');
    final epoch = PqcGroupEpoch(
      epochId: 'epoch-7',
      secretKeyBytes: List<int>.generate(32, (index) => index),
    );
    await sourceVault.saveDeviceKeyset(
      accountId: accountId,
      keyset: device,
      makeCurrent: true,
    );
    await sourceVault.saveGroupEpoch(
      accountId: accountId,
      conversationId: groupConversation.id,
      epoch: epoch,
    );
    await sourceRecovery.synchronize(accountId);
    final payload = await engine.group.encrypt(
      conversation: groupConversation,
      plaintext: 'group history',
      epoch: epoch,
      sender: device,
    );

    final targetVault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    final targetRecovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: targetVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    final retry = PqcDecryptRetryCoordinator(
      manager: PqcEngineManager(decoders: [engine]),
      vault: targetVault,
      recovery: targetRecovery,
      healthMonitor: targetRecovery.healthMonitor,
    );
    final result = await retry.decryptGroup(
      accountId: accountId,
      conversation: groupConversation,
      payload: payload,
      trustedSigningKeysByDevice: {
        device.deviceId: {device.signingPublicKeyBase64},
      },
    );
    expect((result as PqcDecoded).plaintext, 'group history');
  });

  test('group rekey recovery decrypts both old and new epochs', () async {
    final transport = PqcMemoryRecoveryRepository();
    const keyProvider = _FixedRecoveryKeyProvider(27);
    final sourceVault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    final sourceRecovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: sourceVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    final keyset = engine.generateDeviceKeyset('phone');
    final oldEpoch = PqcGroupEpoch(
      epochId: 'epoch-old',
      secretKeyBytes: List<int>.generate(32, (index) => index),
    );
    final newEpoch = PqcGroupEpoch(
      epochId: 'epoch-new',
      secretKeyBytes: List<int>.generate(32, (index) => 255 - index),
    );
    await sourceVault.saveDeviceKeyset(
      accountId: accountId,
      keyset: keyset,
      makeCurrent: true,
    );
    await sourceVault.saveGroupEpoch(
      accountId: accountId,
      conversationId: groupConversation.id,
      epoch: oldEpoch,
    );
    await sourceVault.saveGroupEpoch(
      accountId: accountId,
      conversationId: groupConversation.id,
      epoch: newEpoch,
    );
    await sourceRecovery.synchronize(accountId);
    final oldPayload = await engine.group.encrypt(
      conversation: groupConversation,
      plaintext: 'before rekey',
      epoch: oldEpoch,
      sender: keyset,
    );
    final newPayload = await engine.group.encrypt(
      conversation: groupConversation,
      plaintext: 'after rekey',
      epoch: newEpoch,
      sender: keyset,
    );

    final restoredVault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    final restoredRecovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: restoredVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    final retry = PqcDecryptRetryCoordinator(
      manager: PqcEngineManager(decoders: [engine]),
      vault: restoredVault,
      recovery: restoredRecovery,
      healthMonitor: restoredRecovery.healthMonitor,
    );
    expect(
      (await retry.decryptGroup(
                accountId: accountId,
                conversation: groupConversation,
                payload: oldPayload,
                trustedSigningKeysByDevice: {
                  keyset.deviceId: {keyset.signingPublicKeyBase64},
                },
              )
              as PqcDecoded)
          .plaintext,
      'before rekey',
    );
    expect(
      (await retry.decryptGroup(
                accountId: accountId,
                conversation: groupConversation,
                payload: newPayload,
                trustedSigningKeysByDevice: {
                  keyset.deviceId: {keyset.signingPublicKeyBase64},
                },
              )
              as PqcDecoded)
          .plaintext,
      'after rekey',
    );
  });

  test(
    'recovery rejects tamper, wrong account and concurrent overwrite',
    () async {
      final transport = PqcMemoryRecoveryRepository();
      const keyProvider = _FixedRecoveryKeyProvider(31);
      final vault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final recovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: vault,
        transport: transport,
        keyProvider: keyProvider,
      );
      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: engine.generateDeviceKeyset('phone'),
        makeCurrent: true,
      );
      await recovery.synchronize(accountId);
      final remote = await transport.downloadLatestEncryptedSnapshot(accountId);
      await expectLater(
        recovery.codec.decrypt(
          accountId: 'other-account',
          encryptedBlob: remote!.encryptedBlob,
          recoveryKey: await keyProvider.recoveryKey('other-account'),
        ),
        throwsA(
          isA<PqcRecoveryException>().having(
            (error) => error.failure,
            'failure',
            PqcRecoveryFailure.wrongAccount,
          ),
        ),
      );

      transport.tamperForTest(accountId);
      await expectLater(
        recovery.restoreLatest(accountId),
        throwsA(isA<PqcRecoveryException>()),
      );

      final conflictVault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      await conflictVault.saveDeviceKeyset(
        accountId: accountId,
        keyset: engine.generateDeviceKeyset('second-phone'),
        makeCurrent: true,
      );
      final conflictRecovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: conflictVault,
        transport: _ConflictingRecoveryTransport(),
        keyProvider: keyProvider,
      );
      await expectLater(
        conflictRecovery.synchronize(accountId),
        throwsA(
          isA<PqcRecoveryException>().having(
            (error) => error.failure,
            'failure',
            PqcRecoveryFailure.revisionConflict,
          ),
        ),
      );
    },
  );

  test('recovery rejects a wrong master key and equal-revision fork', () async {
    final transport = PqcMemoryRecoveryRepository();
    const keyProvider = _FixedRecoveryKeyProvider(51);
    final firstVault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    final firstRecovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: firstVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    await firstVault.saveDeviceKeyset(
      accountId: accountId,
      keyset: engine.generateDeviceKeyset('first-phone'),
      makeCurrent: true,
    );
    await firstRecovery.synchronize(accountId);
    final remote = await transport.downloadLatestEncryptedSnapshot(accountId);
    await expectLater(
      firstRecovery.codec.decrypt(
        accountId: accountId,
        encryptedBlob: remote!.encryptedBlob,
        recoveryKey: await const _FixedRecoveryKeyProvider(
          99,
        ).recoveryKey(accountId),
      ),
      throwsA(
        isA<PqcRecoveryException>().having(
          (error) => error.failure,
          'failure',
          PqcRecoveryFailure.corrupted,
        ),
      ),
    );

    final forkVault = PqcIntegrityKeyVault(
      allowInsecureStoreForTesting: true,
      store: PqcMemoryAtomicStore(),
    );
    await forkVault.saveDeviceKeyset(
      accountId: accountId,
      keyset: engine.generateDeviceKeyset('fork-phone'),
      makeCurrent: true,
    );
    final forkRecovery = PqcRecoveryCoordinator(
      allowUnauthenticatedRecoveryForTesting: true,
      vault: forkVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    await expectLater(
      forkRecovery.synchronize(accountId),
      throwsA(
        isA<PqcRecoveryException>().having(
          (error) => error.failure,
          'failure',
          PqcRecoveryFailure.revisionConflict,
        ),
      ),
    );
  });

  test(
    'replay guard distinguishes duplicate from message-id collision',
    () async {
      final guard = PqcReplayGuard(PqcMemoryReplayStore());
      final binding = pqcAccountBinding(accountId);
      expect(
        await guard.claim(
          accountBinding: binding,
          conversationId: 7,
          messageId: 'm-1',
          encryptedPayload: 'cipher-a',
        ),
        PqcReplayDecision.accepted,
      );
      expect(
        await guard.claim(
          accountBinding: binding,
          conversationId: 7,
          messageId: 'm-1',
          encryptedPayload: 'cipher-a',
        ),
        PqcReplayDecision.duplicate,
      );
      expect(
        await guard.claim(
          accountBinding: binding,
          conversationId: 7,
          messageId: 'm-1',
          encryptedPayload: 'cipher-b',
        ),
        PqcReplayDecision.messageIdCollision,
      );
    },
  );

  test('atomic replay claims survive restarts and racing delivery', () async {
    final store = PqcMemoryAtomicStore();
    final firstGuard = PqcReplayGuard(PqcAtomicReplayStore(store));
    final binding = pqcAccountBinding(accountId);
    final decisions = await Future.wait([
      firstGuard.claim(
        accountBinding: binding,
        conversationId: 7,
        messageId: 'durable-message',
        encryptedPayload: 'cipher-a',
      ),
      firstGuard.claim(
        accountBinding: binding,
        conversationId: 7,
        messageId: 'durable-message',
        encryptedPayload: 'cipher-a',
      ),
    ]);
    expect(
      decisions.where((item) => item == PqcReplayDecision.accepted),
      hasLength(1),
    );
    expect(
      decisions.where((item) => item == PqcReplayDecision.duplicate),
      hasLength(1),
    );

    final restartedGuard = PqcReplayGuard(PqcAtomicReplayStore(store));
    expect(
      await restartedGuard.claim(
        accountBinding: binding,
        conversationId: 7,
        messageId: 'durable-message',
        encryptedPayload: 'cipher-b',
      ),
      PqcReplayDecision.messageIdCollision,
    );
  });

  test(
    'health monitor blocks writer until key and recovery are durable',
    () async {
      final health = PqcCryptoHealthMonitor();
      final vault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final writer = PqcV25Writer();
      final recovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: vault,
        transport: PqcMemoryRecoveryRepository(),
        keyProvider: const _FixedRecoveryKeyProvider(41),
        healthMonitor: health,
      );
      final runtime = PqcSecureRuntime(
        manager: PqcEngineManager(
          decoders: [engine],
          activeWriter: writer,
          writerEnabled: true,
          releaseProfile: PqcReleaseProfiles.v25,
        ),
        vault: vault,
        recovery: recovery,
        replayGuard: PqcReplayGuard(PqcMemoryReplayStore()),
        healthMonitor: health,
      );
      await runtime.initializeAccount(accountId);
      expect(
        () => runtime.requireWriter(
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        throwsA(isA<PqcCryptoHealthException>()),
      );

      await runtime.rotateDeviceKeyset(accountId: accountId, deviceId: 'phone');
      expect(
        runtime.requireWriter(
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        same(writer),
      );
      expect(health.snapshot.isSafeToWrite, isTrue);
    },
  );
}
