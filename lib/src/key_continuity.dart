import 'crypto_utils.dart';
import 'models.dart';
import 'secure_key_vault.dart';

enum PqcKeyTransition { initial, unchanged, rotation, historicalImport }

/// Explicit continuity policy shared by local writes and recovery imports.
class PqcKeyContinuityGuard {
  const PqcKeyContinuityGuard();

  PqcKeyTransition inspectDeviceTransition({
    required PqcKeyVaultSnapshot current,
    required PqcDeviceKeyset candidate,
    required bool makeCurrent,
  }) {
    final keysets = <PqcDeviceKeyset>[
      if (current.currentDeviceKeyset != null) current.currentDeviceKeyset!,
      ...current.historicalDeviceKeysets,
    ];
    for (final existing in keysets) {
      if (existing.keysetId == candidate.keysetId) {
        if (!_sameKeyset(existing, candidate)) {
          throw const PqcVaultException(
            PqcVaultFailure.continuityViolation,
            'A keyset id cannot be rebound to different material.',
          );
        }
        return PqcKeyTransition.unchanged;
      }
    }
    if (!makeCurrent) return PqcKeyTransition.historicalImport;
    return current.currentDeviceKeyset == null
        ? PqcKeyTransition.initial
        : PqcKeyTransition.rotation;
  }

  void assertGroupEpochContinuity({
    required PqcGroupEpoch existing,
    required PqcGroupEpoch candidate,
  }) {
    if (existing.epochId != candidate.epochId ||
        !_sameBytes(existing.secretKeyBytes, candidate.secretKeyBytes)) {
      throw const PqcVaultException(
        PqcVaultFailure.continuityViolation,
        'A group epoch id cannot be rebound to different material.',
      );
    }
  }
}

bool _sameKeyset(PqcDeviceKeyset left, PqcDeviceKeyset right) =>
    left.deviceId == right.deviceId &&
    left.kemPublicKeyBase64 == right.kemPublicKeyBase64 &&
    constantTimeStringEquals(
      left.kemSecretKeyBase64,
      right.kemSecretKeyBase64,
    ) &&
    left.signingPublicKeyBase64 == right.signingPublicKeyBase64 &&
    constantTimeStringEquals(
      left.signingSecretKeyBase64,
      right.signingSecretKeyBase64,
    );

bool _sameBytes(List<int> left, List<int> right) =>
    constantTimeBytesEquals(left, right);
