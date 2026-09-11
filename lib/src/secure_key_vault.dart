import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'key_repository.dart';
import 'key_continuity.dart';
import 'models.dart';

enum PqcVaultFailure {
  corrupted,
  accountMismatch,
  continuityViolation,
  writeConflict,
  unavailable,
}

class PqcVaultException implements Exception {
  const PqcVaultException(this.failure, this.message);

  final PqcVaultFailure failure;
  final String message;

  @override
  String toString() => 'PqcVaultException($failure): $message';
}

class PqcAtomicRecord {
  PqcAtomicRecord({
    required this.revision,
    required List<int> bytes,
    required this.sha256,
  }) : bytes = Uint8List.fromList(bytes);

  final int revision;
  final Uint8List bytes;
  final String sha256;

  PqcAtomicRecord copy() =>
      PqcAtomicRecord(revision: revision, bytes: bytes, sha256: sha256);
}

/// Platform-neutral atomic persistence boundary.
///
/// A Keychain, Keystore, encrypted database, IndexedDB or HSM adapter must
/// implement compare-and-set as one durable transaction. Returning `true`
/// means the full record is durable; partial writes must never be observable.
abstract interface class PqcAtomicStore {
  Future<PqcAtomicRecord?> read({
    required String namespace,
    required String key,
  });

  Future<bool> compareAndSet({
    required String namespace,
    required String key,
    required int? expectedRevision,
    required PqcAtomicRecord value,
  });
}

/// Security properties that a production persistence adapter must guarantee.
///
/// Implement this interface only when the record is encrypted with a key that
/// is not stored beside the ciphertext (Android Keystore, Apple Keychain,
/// hardware-backed WebCrypto/HSM, or an equivalent platform facility).
abstract interface class PqcProductionAtomicStore implements PqcAtomicStore {
  bool get encryptedAtRest;

  bool get hardwareBackedKeyProtection;

  bool get atomicDurability;
}

/// Deterministic implementation for tests, CLI tools and host prototypes.
class PqcMemoryAtomicStore implements PqcAtomicStore {
  final Map<String, PqcAtomicRecord> _records = {};

  String _recordKey(String namespace, String key) => '$namespace\u0000$key';

  @override
  Future<PqcAtomicRecord?> read({
    required String namespace,
    required String key,
  }) async {
    return _records[_recordKey(namespace, key)]?.copy();
  }

  @override
  Future<bool> compareAndSet({
    required String namespace,
    required String key,
    required int? expectedRevision,
    required PqcAtomicRecord value,
  }) async {
    final recordKey = _recordKey(namespace, key);
    final current = _records[recordKey];
    if (current?.revision != expectedRevision) return false;
    _records[recordKey] = value.copy();
    return true;
  }

  void corruptForTest({required String namespace, required String key}) {
    final recordKey = _recordKey(namespace, key);
    final current = _records[recordKey];
    if (current == null || current.bytes.isEmpty) return;
    final bytes = current.bytes.toList();
    bytes[0] ^= 0x01;
    _records[recordKey] = PqcAtomicRecord(
      revision: current.revision,
      bytes: bytes,
      sha256: current.sha256,
    );
  }
}

class PqcVaultGroupEpoch {
  const PqcVaultGroupEpoch({required this.conversationId, required this.epoch});

  final int conversationId;
  final PqcGroupEpoch epoch;
}

class PqcKeyVaultSnapshot {
  const PqcKeyVaultSnapshot({
    required this.schemaVersion,
    required this.accountBinding,
    required this.revision,
    required this.currentDeviceKeyset,
    required this.historicalDeviceKeysets,
    required this.groupEpochs,
  });

  static const currentSchemaVersion = 1;

  final int schemaVersion;
  final String accountBinding;
  final int revision;
  final PqcDeviceKeyset? currentDeviceKeyset;
  final List<PqcDeviceKeyset> historicalDeviceKeysets;
  final List<PqcVaultGroupEpoch> groupEpochs;

  bool get hasAnyKeyMaterial =>
      currentDeviceKeyset != null ||
      historicalDeviceKeysets.isNotEmpty ||
      groupEpochs.isNotEmpty;

  Map<String, dynamic> toJson() => {
    'schema_version': schemaVersion,
    'account_binding': accountBinding,
    'revision': revision,
    'current_device_keyset': currentDeviceKeyset == null
        ? null
        : _keysetToJson(currentDeviceKeyset!),
    'historical_device_keysets': historicalDeviceKeysets
        .map(_keysetToJson)
        .toList(growable: false),
    'group_epochs': groupEpochs
        .map(
          (item) => {
            'conversation_id': item.conversationId,
            'epoch_id': item.epoch.epochId,
            'secret_key_base64': base64Encode(item.epoch.secretKeyBytes),
          },
        )
        .toList(growable: false),
  };

  factory PqcKeyVaultSnapshot.fromJson(Map<String, dynamic> json) {
    final currentJson = json['current_device_keyset'];
    if (currentJson != null && currentJson is! Map) {
      throw const FormatException('Current device keyset must be an object.');
    }
    final historicalJson = json['historical_device_keysets'];
    if (historicalJson != null && historicalJson is! List) {
      throw const FormatException('Historical device keysets must be a list.');
    }
    final groupEpochJson = json['group_epochs'];
    if (groupEpochJson != null && groupEpochJson is! List) {
      throw const FormatException('Group epochs must be a list.');
    }
    return PqcKeyVaultSnapshot(
      schemaVersion: json['schema_version'] as int? ?? 0,
      accountBinding: json['account_binding'] as String? ?? '',
      revision: json['revision'] as int? ?? -1,
      currentDeviceKeyset: currentJson is Map
          ? _keysetFromJson(Map<String, dynamic>.from(currentJson))
          : null,
      historicalDeviceKeysets: ((historicalJson as List?) ?? const [])
          .map((item) {
            if (item is! Map) {
              throw const FormatException(
                'Historical device keysets must contain objects.',
              );
            }
            return _keysetFromJson(Map<String, dynamic>.from(item));
          })
          .toList(growable: false),
      groupEpochs: ((groupEpochJson as List?) ?? const [])
          .map((raw) {
            if (raw is! Map) {
              throw const FormatException('Group epochs must contain objects.');
            }
            final item = Map<String, dynamic>.from(raw);
            return PqcVaultGroupEpoch(
              conversationId: item['conversation_id'] as int? ?? -1,
              epoch: PqcGroupEpoch(
                epochId: item['epoch_id'] as String? ?? '',
                secretKeyBytes: base64Decode(
                  item['secret_key_base64'] as String? ?? '',
                ),
              ),
            );
          })
          .toList(growable: false),
    );
  }
}

abstract interface class PqcKeyVaultRepository implements PqcKeyRepository {
  Future<PqcKeyVaultSnapshot> exportSnapshot(String accountId);

  Future<void> mergeSnapshot({
    required String accountId,
    required PqcKeyVaultSnapshot snapshot,
  });

  Future<void> verifyIntegrity(String accountId);

  /// Retires the local current key without deleting its decrypt capability.
  ///
  /// The host remains responsible for revoking the public device record on
  /// the server. The private material is retained as read-only history.
  Future<void> revokeCurrentDeviceKeyset({
    required String accountId,
    required String deviceId,
  });
}

/// Integrity-checked, append-preserving implementation of the SDK key vault.
///
/// It never discards an old current device key during rotation. Conflicting
/// material for the same keyset/epoch id is rejected instead of overwritten.
class PqcIntegrityKeyVault implements PqcKeyVaultRepository {
  PqcIntegrityKeyVault({
    required PqcAtomicStore store,
    PqcKeyContinuityGuard? continuityGuard,
    this.maxCompareAndSetAttempts = 8,
    bool allowInsecureStoreForTesting = false,
  }) : _store = _validatedStore(
         store,
         allowInsecureStoreForTesting: allowInsecureStoreForTesting,
       ),
       _continuityGuard = continuityGuard ?? const PqcKeyContinuityGuard() {
    if (maxCompareAndSetAttempts <= 0) {
      throw ArgumentError.value(
        maxCompareAndSetAttempts,
        'maxCompareAndSetAttempts',
        'Must be greater than zero.',
      );
    }
  }

  static const storageNamespace = 'pqc-engine-sdk.key-vault.v1';
  final PqcAtomicStore _store;
  final PqcKeyContinuityGuard _continuityGuard;
  final int maxCompareAndSetAttempts;

  static PqcAtomicStore _validatedStore(
    PqcAtomicStore store, {
    required bool allowInsecureStoreForTesting,
  }) {
    const productMode = bool.fromEnvironment('dart.vm.product');
    if (store case final PqcProductionAtomicStore production
        when production.encryptedAtRest &&
            production.hardwareBackedKeyProtection &&
            production.atomicDurability) {
      return store;
    }
    if (allowInsecureStoreForTesting && !productMode) return store;
    throw const PqcVaultException(
      PqcVaultFailure.unavailable,
      'Production key storage must provide encrypted-at-rest, hardware-backed '
      'key protection and atomic durability.',
    );
  }

  @override
  Future<PqcDeviceKeyset?> readCurrentDeviceKeyset(String accountId) async {
    return (await _read(accountId)).currentDeviceKeyset;
  }

  @override
  Future<List<PqcDeviceKeyset>> readHistoricalDeviceKeysets(
    String accountId,
  ) async {
    return List.unmodifiable((await _read(accountId)).historicalDeviceKeysets);
  }

  @override
  Future<void> saveDeviceKeyset({
    required String accountId,
    required PqcDeviceKeyset keyset,
    required bool makeCurrent,
  }) async {
    _validateKeyset(keyset);
    await _mutate(accountId, (current) {
      _continuityGuard.inspectDeviceTransition(
        current: current,
        candidate: keyset,
        makeCurrent: makeCurrent,
      );
      final all = <String, PqcDeviceKeyset>{};
      if (current.currentDeviceKeyset case final existing?) {
        all[existing.keysetId] = existing;
      }
      for (final historical in current.historicalDeviceKeysets) {
        _putKeysetChecked(all, historical);
      }
      _putKeysetChecked(all, keyset);

      var nextCurrent = current.currentDeviceKeyset;
      if (makeCurrent) nextCurrent = keyset;
      final historical =
          all.values
              .where((item) => item.keysetId != nextCurrent?.keysetId)
              .toList(growable: false)
            ..sort((left, right) => left.keysetId.compareTo(right.keysetId));
      return _copySnapshot(
        current,
        currentDeviceKeyset: nextCurrent,
        historicalDeviceKeysets: historical,
      );
    });
  }

  @override
  Future<PqcGroupEpoch?> readGroupEpoch({
    required String accountId,
    required int conversationId,
    required String epochId,
  }) async {
    final snapshot = await _read(accountId);
    for (final item in snapshot.groupEpochs) {
      if (item.conversationId == conversationId &&
          item.epoch.epochId == epochId) {
        return PqcGroupEpoch(
          epochId: item.epoch.epochId,
          secretKeyBytes: item.epoch.secretKeyBytes,
        );
      }
    }
    return null;
  }

  @override
  Future<void> saveGroupEpoch({
    required String accountId,
    required int conversationId,
    required PqcGroupEpoch epoch,
  }) async {
    _validateEpoch(conversationId, epoch);
    await _mutate(accountId, (current) {
      final epochs = [...current.groupEpochs];
      final existingIndex = epochs.indexWhere(
        (item) =>
            item.conversationId == conversationId &&
            item.epoch.epochId == epoch.epochId,
      );
      if (existingIndex >= 0) {
        _continuityGuard.assertGroupEpochContinuity(
          existing: epochs[existingIndex].epoch,
          candidate: epoch,
        );
        return current;
      }
      epochs.add(
        PqcVaultGroupEpoch(conversationId: conversationId, epoch: epoch),
      );
      epochs.sort((left, right) {
        final conversation = left.conversationId.compareTo(
          right.conversationId,
        );
        return conversation != 0
            ? conversation
            : left.epoch.epochId.compareTo(right.epoch.epochId);
      });
      return _copySnapshot(current, groupEpochs: epochs);
    });
  }

  @override
  Future<PqcKeyVaultSnapshot> exportSnapshot(String accountId) =>
      _read(accountId);

  @override
  Future<void> mergeSnapshot({
    required String accountId,
    required PqcKeyVaultSnapshot snapshot,
  }) async {
    _validateSnapshot(snapshot, expectedAccountId: accountId);
    await _mutate(accountId, (local) {
      final keysets = <String, PqcDeviceKeyset>{};
      if (local.currentDeviceKeyset case final value?) {
        keysets[value.keysetId] = value;
      }
      for (final value in local.historicalDeviceKeysets) {
        _putKeysetChecked(keysets, value);
      }
      if (snapshot.currentDeviceKeyset case final value?) {
        _putKeysetChecked(keysets, value);
      }
      for (final value in snapshot.historicalDeviceKeysets) {
        _putKeysetChecked(keysets, value);
      }
      final nextCurrent =
          local.currentDeviceKeyset ?? snapshot.currentDeviceKeyset;
      final historical =
          keysets.values
              .where((item) => item.keysetId != nextCurrent?.keysetId)
              .toList(growable: false)
            ..sort((left, right) => left.keysetId.compareTo(right.keysetId));

      final epochs = <String, PqcVaultGroupEpoch>{};
      for (final item in [...local.groupEpochs, ...snapshot.groupEpochs]) {
        _validateEpoch(item.conversationId, item.epoch);
        final key = '${item.conversationId}|${item.epoch.epochId}';
        final existing = epochs[key];
        if (existing != null &&
            !_bytesEqual(
              existing.epoch.secretKeyBytes,
              item.epoch.secretKeyBytes,
            )) {
          throw const PqcVaultException(
            PqcVaultFailure.continuityViolation,
            'Recovery contains a conflicting group epoch.',
          );
        }
        epochs[key] = item;
      }
      final epochList = epochs.values.toList(growable: false)
        ..sort((left, right) {
          final conversation = left.conversationId.compareTo(
            right.conversationId,
          );
          return conversation != 0
              ? conversation
              : left.epoch.epochId.compareTo(right.epoch.epochId);
        });
      return _copySnapshot(
        local,
        revision: snapshot.revision > local.revision
            ? snapshot.revision
            : local.revision,
        currentDeviceKeyset: nextCurrent,
        historicalDeviceKeysets: historical,
        groupEpochs: epochList,
      );
    });
  }

  @override
  Future<void> verifyIntegrity(String accountId) async {
    await _read(accountId);
  }

  @override
  Future<void> revokeCurrentDeviceKeyset({
    required String accountId,
    required String deviceId,
  }) async {
    if (deviceId.trim().isEmpty) {
      throw ArgumentError.value(deviceId, 'deviceId', 'Must not be empty.');
    }
    await _mutate(accountId, (current) {
      final active = current.currentDeviceKeyset;
      if (active == null) return current;
      if (active.deviceId != deviceId) {
        throw const PqcVaultException(
          PqcVaultFailure.continuityViolation,
          'Cannot revoke a device that is not the current local keyset.',
        );
      }
      final historical =
          <String, PqcDeviceKeyset>{
              for (final value in current.historicalDeviceKeysets)
                value.keysetId: value,
              active.keysetId: active,
            }.values.toList(growable: false)
            ..sort((left, right) => left.keysetId.compareTo(right.keysetId));
      return _copySnapshot(
        current,
        clearCurrentDeviceKeyset: true,
        historicalDeviceKeysets: historical,
      );
    });
  }

  Future<PqcKeyVaultSnapshot> _read(String accountId) async {
    _requireAccountId(accountId);
    final record = await _readRecord(accountId);
    if (record == null) return _emptySnapshot(accountId);
    if (record.revision < 1) {
      throw const PqcVaultException(
        PqcVaultFailure.corrupted,
        'Stored key vault revision is invalid.',
      );
    }
    final actualHash = _sha256Hex(record.bytes);
    if (!_constantTimeStringEquals(actualHash, record.sha256)) {
      throw const PqcVaultException(
        PqcVaultFailure.corrupted,
        'Stored key vault checksum is invalid.',
      );
    }
    try {
      final decoded = jsonDecode(
        utf8.decode(record.bytes, allowMalformed: false),
      );
      if (decoded is! Map) throw const FormatException();
      final snapshot = PqcKeyVaultSnapshot.fromJson(
        Map<String, dynamic>.from(decoded),
      );
      if (snapshot.revision != record.revision) {
        throw const PqcVaultException(
          PqcVaultFailure.corrupted,
          'Stored key vault revision is inconsistent.',
        );
      }
      _validateSnapshot(snapshot, expectedAccountId: accountId);
      return snapshot;
    } on PqcVaultException {
      rethrow;
    } catch (_) {
      throw const PqcVaultException(
        PqcVaultFailure.corrupted,
        'Stored key vault is malformed.',
      );
    }
  }

  Future<void> _mutate(
    String accountId,
    PqcKeyVaultSnapshot Function(PqcKeyVaultSnapshot current) change,
  ) async {
    _requireAccountId(accountId);
    for (var attempt = 0; attempt < maxCompareAndSetAttempts; attempt++) {
      final current = await _read(accountId);
      final changed = change(current);
      _validateSnapshot(changed, expectedAccountId: accountId);
      if (_snapshotMaterialEquals(current, changed) &&
          changed.revision <= current.revision) {
        return;
      }
      final nextRevision = changed.revision > current.revision
          ? changed.revision
          : current.revision + 1;
      final next = _copySnapshot(changed, revision: nextRevision);
      final bytes = utf8.encode(jsonEncode(next.toJson()));
      final saved = await _compareAndSet(
        accountId: accountId,
        expectedRevision: current.revision == 0 ? null : current.revision,
        value: PqcAtomicRecord(
          revision: next.revision,
          bytes: bytes,
          sha256: _sha256Hex(bytes),
        ),
      );
      if (saved) return;
    }
    throw const PqcVaultException(
      PqcVaultFailure.writeConflict,
      'Atomic key vault update exceeded its retry limit.',
    );
  }

  Future<PqcAtomicRecord?> _readRecord(String accountId) async {
    try {
      return await _store.read(
        namespace: storageNamespace,
        key: _accountKey(accountId),
      );
    } on PqcVaultException {
      rethrow;
    } catch (_) {
      throw const PqcVaultException(
        PqcVaultFailure.unavailable,
        'Key vault storage is unavailable.',
      );
    }
  }

  Future<bool> _compareAndSet({
    required String accountId,
    required int? expectedRevision,
    required PqcAtomicRecord value,
  }) async {
    try {
      return await _store.compareAndSet(
        namespace: storageNamespace,
        key: _accountKey(accountId),
        expectedRevision: expectedRevision,
        value: value,
      );
    } on PqcVaultException {
      rethrow;
    } catch (_) {
      throw const PqcVaultException(
        PqcVaultFailure.unavailable,
        'Key vault storage is unavailable.',
      );
    }
  }
}

PqcKeyVaultSnapshot _emptySnapshot(String accountId) => PqcKeyVaultSnapshot(
  schemaVersion: PqcKeyVaultSnapshot.currentSchemaVersion,
  accountBinding: pqcAccountBinding(accountId),
  revision: 0,
  currentDeviceKeyset: null,
  historicalDeviceKeysets: const [],
  groupEpochs: const [],
);

PqcKeyVaultSnapshot _copySnapshot(
  PqcKeyVaultSnapshot source, {
  int? revision,
  PqcDeviceKeyset? currentDeviceKeyset,
  bool clearCurrentDeviceKeyset = false,
  List<PqcDeviceKeyset>? historicalDeviceKeysets,
  List<PqcVaultGroupEpoch>? groupEpochs,
}) => PqcKeyVaultSnapshot(
  schemaVersion: source.schemaVersion,
  accountBinding: source.accountBinding,
  revision: revision ?? source.revision,
  currentDeviceKeyset: clearCurrentDeviceKeyset
      ? null
      : currentDeviceKeyset ?? source.currentDeviceKeyset,
  historicalDeviceKeysets:
      historicalDeviceKeysets ?? source.historicalDeviceKeysets,
  groupEpochs: groupEpochs ?? source.groupEpochs,
);

void _validateSnapshot(
  PqcKeyVaultSnapshot snapshot, {
  required String expectedAccountId,
}) {
  if (snapshot.schemaVersion != PqcKeyVaultSnapshot.currentSchemaVersion ||
      snapshot.revision < 0) {
    throw const PqcVaultException(
      PqcVaultFailure.corrupted,
      'Unsupported key vault schema or revision.',
    );
  }
  if (!_constantTimeStringEquals(
    snapshot.accountBinding,
    pqcAccountBinding(expectedAccountId),
  )) {
    throw const PqcVaultException(
      PqcVaultFailure.accountMismatch,
      'Key vault belongs to another account.',
    );
  }
  final keysets = <String, PqcDeviceKeyset>{};
  if (snapshot.currentDeviceKeyset case final value?) {
    _validateKeyset(value);
    keysets[value.keysetId] = value;
  }
  for (final keyset in snapshot.historicalDeviceKeysets) {
    _validateKeyset(keyset);
    _putKeysetChecked(keysets, keyset);
  }
  for (final item in snapshot.groupEpochs) {
    _validateEpoch(item.conversationId, item.epoch);
  }
}

void _validateKeyset(PqcDeviceKeyset keyset) {
  if (keyset.deviceId.trim().isEmpty) {
    throw const PqcVaultException(
      PqcVaultFailure.corrupted,
      'Device id is missing from a keyset.',
    );
  }
  // Validate the identity delimiter policy at the vault boundary instead of
  // deferring a malformed keyset until a decrypt attempt.
  keyset.keysetId;
  try {
    if (base64Decode(keyset.kemPublicKeyBase64).length != 1184 ||
        base64Decode(keyset.kemSecretKeyBase64).length != 2400 ||
        base64Decode(keyset.signingPublicKeyBase64).length != 1952 ||
        base64Decode(keyset.signingSecretKeyBase64).length != 4032) {
      throw const FormatException();
    }
  } catch (_) {
    throw const PqcVaultException(
      PqcVaultFailure.corrupted,
      'A device keyset has invalid key lengths.',
    );
  }
}

void _validateEpoch(int conversationId, PqcGroupEpoch epoch) {
  if (conversationId <= 0 ||
      epoch.epochId.trim().isEmpty ||
      epoch.secretKeyBytes.length != 32) {
    throw const PqcVaultException(
      PqcVaultFailure.corrupted,
      'A group epoch has invalid metadata or key length.',
    );
  }
}

void _putKeysetChecked(
  Map<String, PqcDeviceKeyset> keysets,
  PqcDeviceKeyset value,
) {
  final existing = keysets[value.keysetId];
  if (existing != null && !_keysetsEqual(existing, value)) {
    throw const PqcVaultException(
      PqcVaultFailure.continuityViolation,
      'A keyset id cannot be rebound to different secret material.',
    );
  }
  keysets[value.keysetId] = value;
}

Map<String, dynamic> _keysetToJson(PqcDeviceKeyset value) => {
  'device_id': value.deviceId,
  'kem_public_key_base64': value.kemPublicKeyBase64,
  'kem_secret_key_base64': value.kemSecretKeyBase64,
  'signing_public_key_base64': value.signingPublicKeyBase64,
  'signing_secret_key_base64': value.signingSecretKeyBase64,
};

PqcDeviceKeyset _keysetFromJson(Map<String, dynamic> json) => PqcDeviceKeyset(
  deviceId: json['device_id'] as String? ?? '',
  kemPublicKeyBase64: json['kem_public_key_base64'] as String? ?? '',
  kemSecretKeyBase64: json['kem_secret_key_base64'] as String? ?? '',
  signingPublicKeyBase64: json['signing_public_key_base64'] as String? ?? '',
  signingSecretKeyBase64: json['signing_secret_key_base64'] as String? ?? '',
);

bool _keysetsEqual(PqcDeviceKeyset left, PqcDeviceKeyset right) =>
    left.deviceId == right.deviceId &&
    left.kemPublicKeyBase64 == right.kemPublicKeyBase64 &&
    left.kemSecretKeyBase64 == right.kemSecretKeyBase64 &&
    left.signingPublicKeyBase64 == right.signingPublicKeyBase64 &&
    left.signingSecretKeyBase64 == right.signingSecretKeyBase64;

bool _snapshotMaterialEquals(
  PqcKeyVaultSnapshot left,
  PqcKeyVaultSnapshot right,
) =>
    jsonEncode({...left.toJson(), 'revision': 0}) ==
    jsonEncode({...right.toJson(), 'revision': 0});

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

bool _constantTimeStringEquals(String left, String right) =>
    _bytesEqual(utf8.encode(left), utf8.encode(right));

String _sha256Hex(List<int> bytes) => crypto.sha256
    .convert(bytes)
    .bytes
    .map((b) => b.toRadixString(16).padLeft(2, '0'))
    .join();

String pqcAccountBinding(String accountId) {
  _requireAccountId(accountId);
  return _sha256Hex(utf8.encode('pqc-account-v1|$accountId'));
}

String _accountKey(String accountId) => pqcAccountBinding(accountId);

void _requireAccountId(String accountId) {
  if (accountId.trim().isEmpty) {
    throw ArgumentError.value(accountId, 'accountId', 'Must not be empty.');
  }
}
