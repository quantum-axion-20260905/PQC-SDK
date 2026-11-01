import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

import 'crypto_utils.dart';
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
  PqcMemoryReplayStore({this.maxEntries = 50000});

  final int maxEntries;
  final Map<String, String> _claims = {};

  int get entryCount => _claims.length;

  void clear() => _claims.clear();

  @override
  Future<String?> claim({
    required String accountBinding,
    required int conversationId,
    required String messageId,
    required String payloadDigest,
  }) async {
    final key = '$accountBinding|$conversationId|$messageId';
    final existing = _claims[key];
    if (existing == null) {
      if (maxEntries > 0 && _claims.length >= maxEntries) {
        // Evict oldest entry (FIFO sliding window)
        _claims.remove(_claims.keys.first);
      }
      _claims[key] = payloadDigest;
    }
    return existing;
  }
}

/// Durable replay claims backed by the same atomic storage contract as keys.
class PqcAtomicReplayStore implements PqcReplayStore {
  const PqcAtomicReplayStore(this._store, {this.maxEntries = 0});

  static const storageNamespace = 'pqc-engine-sdk.replay.v1';
  static const _journalKey = '_pqc_replay_journal_v1';
  final PqcAtomicStore _store;
  final int maxEntries;

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
      final digest = _validatedDigest(existing);
      if (digest != '0' * 64) {
        return digest;
      }
    }
    final bytes = utf8.encode(normalizedPayloadDigest);
    final saved = await _compareAndSet(
      key: opaqueKey,
      expectedRevision: existing?.revision,
      value: PqcAtomicRecord(
        revision: (existing?.revision ?? 0) + 1,
        bytes: bytes,
        sha256: crypto.sha256.convert(bytes).toString(),
      ),
    );
    if (saved) {
      if (maxEntries > 0) {
        await _recordInJournal(opaqueKey);
      }
      return null;
    }
    final winner = await _read(opaqueKey);
    if (winner == null) {
      throw const PqcVaultException(
        PqcVaultFailure.unavailable,
        'Replay claim disappeared after a concurrent write.',
      );
    }
    return _validatedDigest(winner);
  }

  Future<void> _recordInJournal(String opaqueKey) async {
    for (var attempt = 0; attempt < 5; attempt++) {
      final current = await _read(_journalKey);
      var keys = <String>[];
      int? expectedRevision;
      if (current != null) {
        expectedRevision = current.revision;
        try {
          final decoded = jsonDecode(utf8.decode(current.bytes));
          if (decoded is List) {
            keys = decoded.map((e) => e.toString()).toList();
          }
        } catch (_) {}
      }

      keys.add(opaqueKey);
      String? evictedKey;
      if (maxEntries > 0 && keys.length > maxEntries) {
        evictedKey = keys.removeAt(0);
      }

      final newBytes = utf8.encode(jsonEncode(keys));
      final success = await _compareAndSet(
        key: _journalKey,
        expectedRevision: expectedRevision,
        value: PqcAtomicRecord(
          revision: (expectedRevision ?? 0) + 1,
          bytes: newBytes,
          sha256: crypto.sha256.convert(newBytes).toString(),
        ),
      );

      if (success) {
        if (evictedKey != null) {
          final old = await _read(evictedKey);
          if (old != null) {
            final tombstone = utf8.encode('0' * 64);
            await _compareAndSet(
              key: evictedKey,
              expectedRevision: old.revision,
              value: PqcAtomicRecord(
                revision: old.revision + 1,
                bytes: tombstone,
                sha256: crypto.sha256.convert(tombstone).toString(),
              ),
            );
          }
        }
        break;
      }
    }
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
    return constantTimeStringEquals(existing.toLowerCase(), digest)
        ? PqcReplayDecision.duplicate
        : PqcReplayDecision.messageIdCollision;
  }
}

bool _isSha256Hex(String value) {
  if (value.length != 64) return false;
  for (var i = 0; i < 64; i++) {
    final code = value.codeUnitAt(i);
    final isDigit = code >= 0x30 && code <= 0x39;
    final isLower = code >= 0x61 && code <= 0x66;
    final isUpper = code >= 0x41 && code <= 0x46;
    if (!isDigit && !isLower && !isUpper) return false;
  }
  return true;
}
