import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

abstract final class PqcV2Wire {
  static const protocolVersion = 2;
  static const privatePrefix = 'pqc:v2';
  static const groupPrefix = 'group:v2';

  /// Transitional alias for authenticated V2 group payloads emitted by the
  /// previous release. New production writes use [groupPrefix] directly.
  static const authenticatedGroupPrefix = 'group:v2-auth';
  static const groupWrapPrefix = 'group-wrap:pqc:v2';
  static const privateAlgorithm = 'ml-kem-768+a256gcm+ml-dsa-65';
  static const groupAlgorithm = 'a256gcm+group-ml-kem-768+ml-dsa-65';
  static const legacyGroupAlgorithm = 'a256gcm+group-ml-kem-768';
  static const authenticatedGroupAlgorithm = groupAlgorithm;
  static const groupEnvelopeAlgorithm = 'group-ml-kem-768-aesgcm-v2';
  static const attachmentCipherVersion = 'attachment:v2';
}

/// Immutable wire contract for the independently versioned V3 engine.
///
/// V3 deliberately has a different prefix from V2.  A receiver therefore
/// chooses a decoder from the authenticated payload format before it attempts
/// any cryptographic operation; it must never "try V2" after a V3 failure.
abstract final class PqcV3Wire {
  static const protocolVersion = 3;
  static const privatePrefix = 'pqc:v3';
  static const groupPrefix = 'group:v3';
  static const attachmentCipherVersion = 'attachment:v3';
  static const privateAlgorithm = 'ml-kem-768+a256gcm+ml-dsa-65';
  static const groupAlgorithm = 'ml-kem-768+recipient-wraps+a256gcm+ml-dsa-65';
}

class PqcConversation {
  const PqcConversation({required this.id, required this.type});

  final int id;
  final String type;

  bool get isPrivate => type == 'private';

  bool get isGroup => type == 'group';

  bool get isSupportedType => isPrivate || isGroup;
}

class PqcDevicePublicKey {
  const PqcDevicePublicKey({
    required this.deviceId,
    required this.kemPublicKeyBase64,
    required this.signingPublicKeyBase64,
  });

  final String deviceId;
  final String kemPublicKeyBase64;
  final String signingPublicKeyBase64;

  String get keysetId => computeKeysetId(deviceId, kemPublicKeyBase64);
}

class PqcDeviceKeyset {
  const PqcDeviceKeyset({
    required this.deviceId,
    required this.kemPublicKeyBase64,
    required this.kemSecretKeyBase64,
    required this.signingPublicKeyBase64,
    required this.signingSecretKeyBase64,
  });

  final String deviceId;
  final String kemPublicKeyBase64;
  final String kemSecretKeyBase64;
  final String signingPublicKeyBase64;
  final String signingSecretKeyBase64;

  String get keysetId => computeKeysetId(deviceId, kemPublicKeyBase64);

  PqcDevicePublicKey get publicKey => PqcDevicePublicKey(
    deviceId: deviceId,
    kemPublicKeyBase64: kemPublicKeyBase64,
    signingPublicKeyBase64: signingPublicKeyBase64,
  );
}

class PqcGroupEpoch {
  PqcGroupEpoch({required this.epochId, required List<int> secretKeyBytes})
    : secretKeyBytes = Uint8List.fromList(secretKeyBytes);

  final String epochId;
  final Uint8List secretKeyBytes;
}

class PqcGroupPayloadMetadata {
  const PqcGroupPayloadMetadata({
    required this.conversationId,
    required this.conversationType,
    required this.epochId,
  });

  final int conversationId;
  final String conversationType;
  final String epochId;
}

enum PqcDecodeFailure {
  unsupported,
  bindingMismatch,
  untrustedSender,
  keyMissing,
  corrupted,
}

sealed class PqcDecodeResult {
  const PqcDecodeResult();

  bool get isSuccess => this is PqcDecoded;
}

class PqcDecoded extends PqcDecodeResult {
  const PqcDecoded({required this.plaintext, required this.protocolVersion});

  final String plaintext;
  final int protocolVersion;
}

class PqcDecodeError extends PqcDecodeResult {
  const PqcDecodeError(this.failure, {this.details = ''});

  final PqcDecodeFailure failure;
  final String details;
}

class PqcRemoteCapabilities {
  const PqcRemoteCapabilities({
    required this.privateReadPrefixes,
    required this.groupReadPrefixes,
    required this.privateWritePrefixes,
    required this.groupWritePrefixes,
    required this.privateAlgorithms,
    required this.groupAlgorithms,
    required this.attachmentCipherVersions,
    required this.minimumDecoderVersion,
  });

  final Set<String> privateReadPrefixes;
  final Set<String> groupReadPrefixes;
  final Set<String> privateWritePrefixes;
  final Set<String> groupWritePrefixes;
  final Set<String> privateAlgorithms;
  final Set<String> groupAlgorithms;
  final Set<String> attachmentCipherVersions;
  final int minimumDecoderVersion;
}

String computeKeysetId(String deviceId, String kemPublicKeyBase64) {
  // Keyset ids are part of the frozen V2/V3 wire contracts. Keep the legacy
  // hash formula, but reject its delimiter so two identities cannot share the
  // same preimage, e.g. a|b plus c versus a plus b|c.
  if (deviceId.contains('|')) {
    throw ArgumentError.value(
      deviceId,
      'deviceId',
      'The device id must not contain the keyset-id delimiter "|".',
    );
  }
  final digest = crypto.sha256.convert(
    utf8.encode('$deviceId|$kemPublicKeyBase64'),
  );
  return base64UrlEncode(digest.bytes).replaceAll('=', '');
}
