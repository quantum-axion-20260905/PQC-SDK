import 'dart:convert';

import 'models.dart';

/// Signed V3 wire envelope.  This is intentionally a small data object: key
/// resolution and crypto live in the private/group codecs, not in parsing.
class PqcV3Envelope {
  const PqcV3Envelope({
    required this.isGroup,
    required this.messageId,
    required this.senderDeviceId,
    required this.keysetId,
    required this.ciphertext,
    this.metadata = const {},
    this.conversationId,
    this.conversationType,
    this.senderKeysetId,
    this.signingPublicKey,
    this.wraps = const [],
    this.signature,
  });

  final bool isGroup;
  final String messageId;
  final String senderDeviceId;
  final String keysetId;
  final String ciphertext;
  final Map<String, dynamic> metadata;
  final int? conversationId;
  final String? conversationType;
  final String? senderKeysetId;
  final String? signingPublicKey;
  final List<PqcV3RecipientWrap> wraps;
  final String? signature;

  String get prefix =>
      isGroup ? PqcV3Wire.groupPrefix : PqcV3Wire.privatePrefix;

  Map<String, dynamic> toJson({bool includeSignature = true}) => {
    'protocol_version': PqcV3Wire.protocolVersion,
    'message_id': messageId,
    'sender_device_id': senderDeviceId,
    'keyset_id': keysetId,
    'ciphertext': ciphertext,
    'metadata': metadata,
    if (conversationId != null) 'conversation_id': conversationId,
    if (conversationType != null) 'conversation_type': conversationType,
    if (senderKeysetId != null) 'sender_keyset_id': senderKeysetId,
    if (signingPublicKey != null) 'signing_public_key': signingPublicKey,
    if (wraps.isNotEmpty) 'wraps': wraps.map((item) => item.toJson()).toList(),
    if (includeSignature && signature != null) 'signature': signature,
  };

  /// Exact canonical bytes signed by V3.  Never change key insertion order.
  String unsignedCanonicalJson() => jsonEncode(toJson(includeSignature: false));

  String encode() =>
      '$prefix:${base64UrlEncode(utf8.encode(jsonEncode(toJson())))}';

  static PqcV3Envelope decode(String payload) {
    final isGroup = payload.startsWith('${PqcV3Wire.groupPrefix}:');
    final isPrivate = payload.startsWith('${PqcV3Wire.privatePrefix}:');
    if (!isGroup && !isPrivate) {
      throw const FormatException('Unsupported V3 payload prefix.');
    }
    final prefix = isGroup ? PqcV3Wire.groupPrefix : PqcV3Wire.privatePrefix;
    final encoded = payload.substring(prefix.length + 1);
    final decoded = _decodeDocument(encoded);
    if (decoded['protocol_version'] != PqcV3Wire.protocolVersion) {
      throw const FormatException('Unsupported V3 protocol version.');
    }
    final wraps = decoded['wraps'];
    if (wraps != null && wraps is! List) {
      throw const FormatException('V3 recipient wraps must be a list.');
    }
    final parsedWraps = wraps == null
        ? const <PqcV3RecipientWrap>[]
        : (wraps as List)
              .map((item) {
                if (item is! Map) {
                  throw const FormatException(
                    'V3 recipient wraps must contain objects.',
                  );
                }
                return PqcV3RecipientWrap.fromJson(
                  Map<String, dynamic>.from(item),
                );
              })
              .toList(growable: false);
    return PqcV3Envelope(
      isGroup: isGroup,
      messageId: decoded['message_id'] as String? ?? '',
      senderDeviceId: decoded['sender_device_id'] as String? ?? '',
      keysetId: decoded['keyset_id'] as String? ?? '',
      ciphertext: decoded['ciphertext'] as String? ?? '',
      metadata: Map<String, dynamic>.from(
        decoded['metadata'] as Map? ?? const {},
      ),
      conversationId: decoded['conversation_id'] as int?,
      conversationType: decoded['conversation_type'] as String?,
      senderKeysetId: decoded['sender_keyset_id'] as String?,
      signingPublicKey: decoded['signing_public_key'] as String?,
      wraps: parsedWraps,
      signature: decoded['signature'] as String?,
    );
  }
}

class PqcV3RecipientWrap {
  const PqcV3RecipientWrap({
    required this.deviceId,
    required this.keysetId,
    required this.kemCiphertext,
    required this.wrappedKey,
  });

  final String deviceId;
  final String keysetId;
  final String kemCiphertext;
  final String wrappedKey;

  Map<String, dynamic> toJson() => {
    'device_id': deviceId,
    'keyset_id': keysetId,
    'kem_ciphertext': kemCiphertext,
    'wrapped_key': wrappedKey,
  };

  factory PqcV3RecipientWrap.fromJson(Map<String, dynamic> json) =>
      PqcV3RecipientWrap(
        deviceId: json['device_id'] as String? ?? '',
        keysetId: json['keyset_id'] as String? ?? '',
        kemCiphertext: json['kem_ciphertext'] as String? ?? '',
        wrappedKey: json['wrapped_key'] as String? ?? '',
      );
}

Map<String, dynamic> _decodeDocument(String encoded) {
  final padded = encoded.padRight(
    encoded.length + ((4 - encoded.length % 4) % 4),
    '=',
  );
  final value = jsonDecode(
    utf8.decode(base64Url.decode(padded), allowMalformed: false),
  );
  if (value is! Map<Object?, Object?>) {
    throw const FormatException('V3 payload document must be an object.');
  }
  return Map<String, dynamic>.from(value);
}
