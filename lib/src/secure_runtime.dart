import 'health_monitor.dart';
import 'models.dart';
import 'recovery.dart';
import 'replay_guard.dart';
import 'secure_key_vault.dart';
import 'v2_engine.dart';
import 'v3_attachment_codec.dart';
import 'version_manager.dart';

class PqcSecureRuntimeException implements Exception {
  const PqcSecureRuntimeException(this.message);

  final String message;

  @override
  String toString() => 'PqcSecureRuntimeException: $message';
}

class PqcDecryptRetryCoordinator {
  const PqcDecryptRetryCoordinator({
    required this.manager,
    required this.vault,
    required this.recovery,
    required this.healthMonitor,
    this.sessionGuard,
  });

  final PqcEngineManager manager;
  final PqcKeyVaultRepository vault;
  final PqcRecoveryCoordinator recovery;
  final PqcCryptoHealthMonitor healthMonitor;
  final void Function(String accountId)? sessionGuard;

  Future<PqcDecodeResult> decryptPrivate({
    required String accountId,
    required PqcConversation conversation,
    required String payload,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    sessionGuard?.call(accountId);
    PqcEngine decoder;
    try {
      decoder = manager.resolveDecoder(
        kind: PqcConversationKind.private,
        payload: payload,
      );
    } on PqcCompatibilityException catch (error) {
      return PqcDecodeError(
        PqcDecodeFailure.unsupported,
        details: error.message,
      );
    }

    Future<PqcDecodeResult> attempt() async {
      final current = await _vaultCall(
        () => vault.readCurrentDeviceKeyset(accountId),
      );
      final historical = await _vaultCall(
        () => vault.readHistoricalDeviceKeysets(accountId),
      );
      return decoder.decryptPrivate(
        conversation: conversation,
        payload: payload,
        localKeysets: [?current, ...historical],
        trustedSigningKeysByDevice: trustedSigningKeysByDevice,
      );
    }

    final first = await attempt();
    if (first is! PqcDecodeError ||
        first.failure != PqcDecodeFailure.keyMissing) {
      return first;
    }
    if (!await recovery.restoreLatest(accountId)) return first;
    final retried = await attempt();
    if (retried is PqcDecoded &&
        await _vaultCall(() => vault.readCurrentDeviceKeyset(accountId)) !=
            null) {
      healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
    }
    return retried;
  }

  Future<PqcDecodeResult> decryptGroup({
    required String accountId,
    required PqcConversation conversation,
    required String payload,
    Map<String, Set<String>> trustedSigningKeysByDevice = const {},
  }) async {
    sessionGuard?.call(accountId);
    PqcEngine decoder;
    try {
      decoder = manager.resolveDecoder(
        kind: PqcConversationKind.group,
        payload: payload,
      );
    } on PqcCompatibilityException catch (error) {
      return PqcDecodeError(
        PqcDecodeFailure.unsupported,
        details: error.message,
      );
    }
    final metadata = decoder.inspectGroup(payload);
    if (metadata == null) {
      return const PqcDecodeError(PqcDecodeFailure.corrupted);
    }

    Future<PqcDecodeResult> attempt() async {
      final epochs = <String, PqcGroupEpoch>{};
      // V2 group payloads use an epoch id. V3 group payloads use
      // recipient-device key wraps and intentionally expose an empty epoch id.
      if (metadata.epochId.isNotEmpty) {
        final epoch = await _vaultCall(
          () => vault.readGroupEpoch(
            accountId: accountId,
            conversationId: conversation.id,
            epochId: metadata.epochId,
          ),
        );
        if (epoch != null) epochs[epoch.epochId] = epoch;
      }
      final current = await _vaultCall(
        () => vault.readCurrentDeviceKeyset(accountId),
      );
      final historical = await _vaultCall(
        () => vault.readHistoricalDeviceKeysets(accountId),
      );
      return decoder.decryptGroup(
        conversation: conversation,
        payload: payload,
        epochsById: epochs,
        localKeysets: [?current, ...historical],
        trustedSigningKeysByDevice: trustedSigningKeysByDevice,
      );
    }

    final first = await attempt();
    if (first is! PqcDecodeError ||
        first.failure != PqcDecodeFailure.keyMissing) {
      return first;
    }
    if (!await recovery.restoreLatest(accountId)) return first;
    return attempt();
  }
}

/// Automatic recovery and retry for a recipient-addressed V3 attachment.
///
/// A missing recipient wrap is treated as a recoverable keyset condition. Any
/// signature, metadata or AEAD failure is deliberately not retried and never
/// falls back to a different cipher version.
class PqcV3AttachmentDecryptRetryCoordinator {
  const PqcV3AttachmentDecryptRetryCoordinator({
    required this.vault,
    required this.recovery,
    required this.healthMonitor,
    this.sessionGuard,
  });

  final PqcKeyVaultRepository vault;
  final PqcRecoveryCoordinator recovery;
  final PqcCryptoHealthMonitor healthMonitor;
  final void Function(String accountId)? sessionGuard;

  Future<PqcV3DecryptedAttachment> decrypt({
    required String accountId,
    required PqcConversation conversation,
    required String payload,
    required PqcV3AttachmentCodec codec,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    sessionGuard?.call(accountId);
    Future<PqcV3DecryptedAttachment> attempt() async {
      final current = await _vaultCall(
        () => vault.readCurrentDeviceKeyset(accountId),
      );
      final historical = await _vaultCall(
        () => vault.readHistoricalDeviceKeysets(accountId),
      );
      return codec.decryptForRecipient(
        conversation: conversation,
        payload: payload,
        localKeysets: [?current, ...historical],
        trustedSigningKeysByDevice: trustedSigningKeysByDevice,
      );
    }

    try {
      return await attempt();
    } on PqcV3AttachmentKeyMissingException {
      if (!await recovery.restoreLatest(accountId)) rethrow;
      final restored = await attempt();
      // A historical key can be enough to decrypt this attachment, but it is
      // not enough to make encrypted writes safe. Only a restored current key
      // may clear the writer health issue.
      if (await _vaultCall(() => vault.readCurrentDeviceKeyset(accountId)) !=
          null) {
        healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
      }
      return restored;
    }
  }
}

/// Host-neutral security orchestration around independently versioned engines.
class PqcSecureRuntime {
  PqcSecureRuntime({
    required this.manager,
    required this.vault,
    required this.recovery,
    required this.replayGuard,
    PqcCryptoHealthMonitor? healthMonitor,
  }) : healthMonitor = healthMonitor ?? recovery.healthMonitor {
    if (!identical(this.healthMonitor, recovery.healthMonitor)) {
      throw ArgumentError(
        'PqcSecureRuntime and PqcRecoveryCoordinator must share one '
        'health monitor.',
      );
    }
    decryptRetry = PqcDecryptRetryCoordinator(
      manager: manager,
      vault: vault,
      recovery: recovery,
      healthMonitor: this.healthMonitor,
      sessionGuard: _requireInitialized,
    );
    v3AttachmentDecryptRetry = PqcV3AttachmentDecryptRetryCoordinator(
      vault: vault,
      recovery: recovery,
      healthMonitor: this.healthMonitor,
      sessionGuard: _requireInitialized,
    );
  }

  final PqcEngineManager manager;
  final PqcKeyVaultRepository vault;
  final PqcRecoveryCoordinator recovery;
  final PqcReplayGuard replayGuard;
  final PqcCryptoHealthMonitor healthMonitor;
  late final PqcDecryptRetryCoordinator decryptRetry;
  late final PqcV3AttachmentDecryptRetryCoordinator v3AttachmentDecryptRetry;
  String? _initializedAccountId;

  /// Called after authentication and before messages are loaded or written.
  Future<void> initializeAccount(String accountId) async {
    _requireAccountId(accountId);
    // Invalidate the previous session before a new account is touched. If
    // reinitialization fails, no account can accidentally keep using the
    // writer through this runtime instance.
    _initializedAccountId = null;
    try {
      await _vaultCall(() => vault.verifyIntegrity(accountId));
      healthMonitor.resolve(PqcHealthIssue.storageCorrupted);
      healthMonitor.resolve(PqcHealthIssue.storageUnavailable);
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.corrupted
            ? PqcHealthIssue.storageCorrupted
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    }

    try {
      await recovery.synchronize(accountId);
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.corrupted
            ? PqcHealthIssue.storageCorrupted
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    } on PqcRecoveryException catch (error) {
      healthMonitor.report(
        error.failure == PqcRecoveryFailure.revisionConflict ||
                error.failure == PqcRecoveryFailure.corrupted
            ? PqcHealthIssue.recoveryConflict
            : PqcHealthIssue.recoveryUnavailable,
        blocking: true,
      );
      rethrow;
    }
    try {
      final current = await _vaultCall(
        () => vault.readCurrentDeviceKeyset(accountId),
      );
      if (current == null) {
        healthMonitor.report(PqcHealthIssue.currentKeyMissing, blocking: true);
      } else {
        healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
      }
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.corrupted
            ? PqcHealthIssue.storageCorrupted
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    }
    _initializedAccountId = accountId;
  }

  /// Atomically stores and backs up a new key before the host may publish it.
  Future<PqcDeviceKeyset> rotateDeviceKeyset({
    required String accountId,
    required String deviceId,
  }) async {
    _requireInitialized(accountId);
    final engine = manager.activeWriter;
    if (engine == null) {
      throw const PqcCompatibilityException(
        'No active writer is configured for key rotation.',
      );
    }
    final keyset = engine.generateDeviceKeyset(deviceId);
    try {
      await _vaultCall(
        () => vault.saveDeviceKeyset(
          accountId: accountId,
          keyset: keyset,
          makeCurrent: true,
        ),
      );
      await recovery.synchronize(accountId);
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.continuityViolation
            ? PqcHealthIssue.continuityViolation
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    } on PqcRecoveryException {
      healthMonitor.report(PqcHealthIssue.recoveryUnavailable, blocking: true);
      rethrow;
    }
    healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
    healthMonitor.resolve(PqcHealthIssue.continuityViolation);
    healthMonitor.resolve(PqcHealthIssue.recoveryUnavailable);
    return keyset;
  }

  /// Retires a revoked device key while preserving historical decryption.
  /// A new writer key must be rotated before another encrypted send.
  Future<void> revokeCurrentDevice({
    required String accountId,
    required String deviceId,
  }) async {
    _requireInitialized(accountId);
    try {
      await _vaultCall(
        () => vault.revokeCurrentDeviceKeyset(
          accountId: accountId,
          deviceId: deviceId,
        ),
      );
      await recovery.synchronize(accountId);
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.continuityViolation
            ? PqcHealthIssue.continuityViolation
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      if (error.failure != PqcVaultFailure.continuityViolation) {
        healthMonitor.report(PqcHealthIssue.currentKeyMissing, blocking: true);
      }
      rethrow;
    } on PqcRecoveryException {
      healthMonitor.report(PqcHealthIssue.recoveryUnavailable, blocking: true);
      healthMonitor.report(PqcHealthIssue.currentKeyMissing, blocking: true);
      rethrow;
    }
    healthMonitor.report(PqcHealthIssue.currentKeyMissing, blocking: true);
  }

  /// Persists a received group epoch and its recovery snapshot before ACK.
  Future<void> persistGroupEpochBeforeAck({
    required String accountId,
    required int conversationId,
    required PqcGroupEpoch epoch,
  }) async {
    _requireInitialized(accountId);
    try {
      await _vaultCall(
        () => vault.saveGroupEpoch(
          accountId: accountId,
          conversationId: conversationId,
          epoch: epoch,
        ),
      );
      await recovery.synchronize(accountId);
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.continuityViolation
            ? PqcHealthIssue.continuityViolation
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    } on PqcRecoveryException {
      healthMonitor.report(PqcHealthIssue.recoveryUnavailable, blocking: true);
      rethrow;
    }
  }

  PqcEngine requireWriter({
    required PqcConversationKind kind,
    required PqcRemoteCapabilities remote,
  }) {
    if (_initializedAccountId == null) {
      throw const PqcSecureRuntimeException(
        'Account initialization is required before encrypted writes.',
      );
    }
    healthMonitor.assertSafeToWrite();
    return manager.requireWriter(kind: kind, remote: remote);
  }

  /// Integrity check used directly in the send path before encryption.
  Future<PqcEngine> prepareWriter({
    required String accountId,
    required PqcConversationKind kind,
    required PqcRemoteCapabilities remote,
  }) async {
    _requireInitialized(accountId);
    try {
      await _vaultCall(() => vault.verifyIntegrity(accountId));
      final current = await _vaultCall(
        () => vault.readCurrentDeviceKeyset(accountId),
      );
      if (current == null) {
        healthMonitor.report(PqcHealthIssue.currentKeyMissing, blocking: true);
      } else {
        healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
      }
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.corrupted
            ? PqcHealthIssue.storageCorrupted
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    }
    return requireWriter(kind: kind, remote: remote);
  }

  void _requireInitialized(String accountId) {
    _requireAccountId(accountId);
    if (_initializedAccountId != accountId) {
      throw const PqcSecureRuntimeException(
        'Account must be initialized before this operation.',
      );
    }
  }

  void _requireAccountId(String accountId) {
    if (accountId.trim().isEmpty) {
      throw ArgumentError.value(accountId, 'accountId', 'Must not be empty.');
    }
  }

  Future<PqcReplayDecision> acceptInbound({
    required String accountId,
    required int conversationId,
    required String messageId,
    required String encryptedPayload,
  }) async {
    _requireInitialized(accountId);
    late final PqcReplayDecision decision;
    try {
      decision = await replayGuard.claim(
        accountBinding: pqcAccountBinding(accountId),
        conversationId: conversationId,
        messageId: messageId,
        encryptedPayload: encryptedPayload,
      );
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.corrupted
            ? PqcHealthIssue.storageCorrupted
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    }
    if (decision != PqcReplayDecision.accepted) {
      healthMonitor.report(
        PqcHealthIssue.replayDetected,
        blocking: decision == PqcReplayDecision.messageIdCollision,
        correlationId: messageId,
      );
    }
    return decision;
  }
}

Future<T> _vaultCall<T>(Future<T> Function() operation) async {
  try {
    return await operation();
  } on PqcVaultException {
    rethrow;
  } catch (_) {
    throw const PqcVaultException(
      PqcVaultFailure.unavailable,
      'Key vault is unavailable.',
    );
  }
}
