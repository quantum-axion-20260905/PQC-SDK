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
  static const groupWrapV25Prefix = 'group-wrap:pqc:v2.5';
  static const privateAlgorithm = 'ml-kem-768+a256gcm+ml-dsa-65';
  static const groupAlgorithm = 'a256gcm+group-ml-kem-768+ml-dsa-65';
  static const legacyGroupAlgorithm = 'a256gcm+group-ml-kem-768';
  static const authenticatedGroupAlgorithm = groupAlgorithm;
  static const groupEnvelopeAlgorithm = 'group-ml-kem-768-aesgcm-v2';
  static const groupEnvelopeV25Algorithm = 'group-ml-kem-768-aesgcm-v2.5';
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

  String get bindingId => computeKeysetBindingId(
    deviceId,
    kemPublicKeyBase64,
    signingPublicKeyBase64,
  );
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

  String get bindingId => computeKeysetBindingId(
    deviceId,
    kemPublicKeyBase64,
    signingPublicKeyBase64,
  );

  PqcDevicePublicKey get publicKey => PqcDevicePublicKey(
    deviceId: deviceId,
    kemPublicKeyBase64: kemPublicKeyBase64,
    signingPublicKeyBase64: signingPublicKeyBase64,
  );

  /// Returns a newly allocated byte buffer of the KEM secret key.
  /// The caller should zeroize it with [secureZero] after use.
  Uint8List copyKemSecretKey() => Uint8List.fromList(base64Decode(kemSecretKeyBase64));

  /// Returns a newly allocated byte buffer of the signing secret key.
  /// The caller should zeroize it with [secureZero] after use.
  Uint8List copySigningSecretKey() =>
      Uint8List.fromList(base64Decode(signingSecretKeyBase64));
}

class PqcGroupEpoch {
  PqcGroupEpoch({required this.epochId, required List<int> secretKeyBytes})
    : secretKeyBytes = Uint8List.fromList(secretKeyBytes);

  final String epochId;
  final Uint8List secretKeyBytes;

  /// Securely overwrites the epoch secret key buffer in place.
  void zeroize() {
    for (var i = 0; i < secretKeyBytes.length; i++) {
      secretKeyBytes[i] = 0;
    }
  }
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

String computeKeysetBindingId(
  String deviceId,
  String kemPublicKeyBase64,
  String signingPublicKeyBase64,
) {
  final canonical = jsonEncode({
    'device_id': deviceId,
    'kem_public_key': kemPublicKeyBase64,
    'signing_public_key': signingPublicKeyBase64,
  });
  final digest = crypto.sha256.convert(utf8.encode(canonical));
  return base64UrlEncode(digest.bytes).replaceAll('=', '');
}

/// Shared release catalog used by SDK hosts and the backend capability
/// contract. A release id is not the same thing as a wire protocol: V2.5
/// keeps the V2 message wire format while adding a V2.5 group-key envelope.
class PqcProtocolRelease {
  const PqcProtocolRelease({
    required this.profileId,
    required this.releaseId,
    required this.wireProtocol,
    required this.supportedProtocolIds,
  });

  final String profileId;
  final String releaseId;
  final String wireProtocol;
  final List<String> supportedProtocolIds;

  static const v2ReleaseId = '2.0.0';
  static const v25ReleaseId = '2.5.0';
  static const v3ReleaseId = '3.0.0';

  static const v2 = PqcProtocolRelease(
    profileId: 'v2',
    releaseId: v2ReleaseId,
    wireProtocol: 'v2',
    supportedProtocolIds: ['v2'],
  );

  static const v25 = PqcProtocolRelease(
    profileId: 'v2.5',
    releaseId: v25ReleaseId,
    wireProtocol: 'v2',
    supportedProtocolIds: ['v2', 'v2.5'],
  );

  static const v3 = PqcProtocolRelease(
    profileId: 'v3',
    releaseId: v3ReleaseId,
    wireProtocol: 'v3',
    supportedProtocolIds: ['v2', 'v2.5', 'v3'],
  );

  static PqcProtocolRelease? tryParse(String value) {
    switch (value.trim().toLowerCase()) {
      case 'v2':
      case '2':
      case '2.0':
      case '2.0.0':
        return v2;
      case 'v2.5':
      case 'v25':
      case 'v2_5':
      case '2.5':
      case '2.5.0':
        return v25;
      case 'v3':
      case '3':
      case '3.0':
      case '3.0.0':
        return v3;
      default:
        return null;
    }
  }

  bool supportsProtocol(String protocolId) =>
      supportedProtocolIds.contains(protocolId.trim().toLowerCase());
}
