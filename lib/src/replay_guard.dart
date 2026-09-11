import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

import 'secure_key_vault.dart';

enum PqcReplayDecision { accepted, duplicate, messageIdCollision }

abstract interface class PqcReplayStore {
  /// Atomically stores [payloadDigest] for a new message id and returns the
  /// digest already stored when another caller won the race.
  Future<String?> claim({
    required String accountBinding,
    required int conversationId,
    required String messageId,
    required String payloadDigest,
  });
}

class PqcMemoryReplayStore implements PqcReplayStore {
  final Map<String, String> _claims = {};

  @override
  Future<String?> claim({
    required String accountBinding,
    required int conversationId,
    required String messageId,
    required String payloadDigest,
  }) async {
    final key = '$accountBinding|$conversationId|$messageId';
    final existing = _claims[key];
    if (existing == null) _claims[key] = payloadDigest;
    return existing;
  }
}

/// Durable replay claims backed by the same atomic storage contract as keys.
class PqcAtomicReplayStore implements PqcReplayStore {
  const PqcAtomicReplayStore(this._store);

  static const storageNamespace = 'pqc-engine-sdk.replay.v1';
  final PqcAtomicStore _store;

  @override
  Future<String?> claim({
    required String accountBinding,
    required int conversationId,
    required String messageId,
    required String payloadDigest,
  }) async {
    if (accountBinding.trim().isEmpty ||
        conversationId <= 0 ||
        messageId.trim().isEmpty) {
      throw ArgumentError('Replay identity fields are required.');
    }
    if (!_isSha256Hex(payloadDigest)) {
      throw ArgumentError.value(
        payloadDigest,
        'payloadDigest',
        'Must be a lowercase or uppercase SHA-256 hex digest.',
      );
    }
    final normalizedPayloadDigest = payloadDigest.toLowerCase();
    final opaqueKey = crypto.sha256
        .convert(utf8.encode('$accountBinding|$conversationId|$messageId'))
        .toString();
    final existing = await _read(opaqueKey);
    if (existing != null) {
      return _validatedDigest(existing);
    }
    final bytes = utf8.encode(normalizedPayloadDigest);
    final saved = await _compareAndSet(
      key: opaqueKey,
      expectedRevision: null,
      value: PqcAtomicRecord(
        revision: 1,
        bytes: bytes,
        sha256: crypto.sha256.convert(bytes).toString(),
      ),
    );
    if (saved) return null;
    final winner = await _read(opaqueKey);
    if (winner == null) {
      throw const PqcVaultException(
        PqcVaultFailure.unavailable,
        'Replay claim disappeared after a concurrent write.',
      );
    }
    return _validatedDigest(winner);
  }

  String _validatedDigest(PqcAtomicRecord record) {
    if (record.revision < 1 ||
        crypto.sha256.convert(record.bytes).toString() != record.sha256) {
      throw const PqcVaultException(
        PqcVaultFailure.corrupted,
        'Replay store record is invalid.',
      );
    }
    late final String digest;
    try {
      digest = utf8.decode(record.bytes, allowMalformed: false);
    } on FormatException {
      throw const PqcVaultException(
        PqcVaultFailure.corrupted,
        'Replay store digest is not valid UTF-8.',
      );
    }
    if (!_isSha256Hex(digest)) {
      throw const PqcVaultException(
        PqcVaultFailure.corrupted,
        'Replay store digest has an invalid format.',
      );
    }
    return digest.toLowerCase();
  }

  Future<PqcAtomicRecord?> _read(String key) async {
    try {
      return await _store.read(namespace: storageNamespace, key: key);
    } on PqcVaultException {
      rethrow;
    } catch (_) {
      throw const PqcVaultException(
        PqcVaultFailure.unavailable,
        'Replay store is unavailable.',
      );
    }
  }

  Future<bool> _compareAndSet({
    required String key,
    required int? expectedRevision,
    required PqcAtomicRecord value,
  }) async {
    try {
      return await _store.compareAndSet(
        namespace: storageNamespace,
        key: key,
        expectedRevision: expectedRevision,
        value: value,
      );
    } on PqcVaultException {
      rethrow;
    } catch (_) {
      throw const PqcVaultException(
        PqcVaultFailure.unavailable,
        'Replay store is unavailable.',
      );
    }
  }
}

class PqcReplayGuard {
  const PqcReplayGuard(this._store);

  final PqcReplayStore _store;

  Future<PqcReplayDecision> claim({
    required String accountBinding,
    required int conversationId,
    required String messageId,
    required String encryptedPayload,
  }) async {
    if (accountBinding.trim().isEmpty ||
        conversationId <= 0 ||
        messageId.trim().isEmpty ||
        encryptedPayload.isEmpty) {
      throw ArgumentError('Replay identity and payload fields are required.');
    }
    final digest = crypto.sha256
        .convert(utf8.encode(encryptedPayload))
        .toString();
    late final String? existing;
    try {
      existing = await _store.claim(
        accountBinding: accountBinding,
        conversationId: conversationId,
        messageId: messageId,
        payloadDigest: digest,
      );
    } on PqcVaultException {
      rethrow;
    } catch (_) {
      throw const PqcVaultException(
        PqcVaultFailure.unavailable,
        'Replay store is unavailable.',
      );
    }
    if (existing == null) return PqcReplayDecision.accepted;
    if (!_isSha256Hex(existing)) {
      throw const PqcVaultException(
        PqcVaultFailure.corrupted,
        'Replay store returned an invalid digest.',
      );
    }
    return existing.toLowerCase() == digest
        ? PqcReplayDecision.duplicate
        : PqcReplayDecision.messageIdCollision;
  }
}

bool _isSha256Hex(String value) => RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(value);
