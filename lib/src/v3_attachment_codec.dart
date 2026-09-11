import 'dart:convert';
import 'dart:typed_data';

import 'models.dart';
import 'primitives.dart';
import 'v3_envelope.dart';

/// Small encrypted V3 attachment payload. Transport, persistence and upload
/// retry remain host responsibilities; this codec only authenticates bytes and
/// immutable filename/MIME/size metadata.
class PqcV3EncryptedAttachment {
  const PqcV3EncryptedAttachment({
    required this.filename,
    required this.mimeType,
    required this.sizeBytes,
    required this.ciphertext,
  });

  final String filename;
  final String mimeType;
  final int sizeBytes;
  final String ciphertext;

  Map<String, dynamic> toJson() => {
    'cipher_version': PqcV3Wire.attachmentCipherVersion,
    'filename': filename,
    'mime_type': mimeType,
    'size_bytes': sizeBytes,
    'ciphertext': ciphertext,
  };

  factory PqcV3EncryptedAttachment.fromJson(Map<String, dynamic> json) {
    if (json['cipher_version'] != PqcV3Wire.attachmentCipherVersion) {
      throw const FormatException('Unsupported V3 attachment cipher version.');
    }
    final attachment = PqcV3EncryptedAttachment(
      filename: json['filename'] as String? ?? '',
      mimeType: json['mime_type'] as String? ?? '',
      sizeBytes: json['size_bytes'] as int? ?? -1,
      ciphertext: json['ciphertext'] as String? ?? '',
    );
    attachment._validateMetadata();
    return attachment;
  }

  void _validateMetadata() {
    if (filename.trim().isEmpty ||
        mimeType.trim().isEmpty ||
        sizeBytes < 0 ||
        ciphertext.isEmpty) {
      throw const FormatException('Invalid V3 attachment metadata.');
    }
  }
}

/// Complete recipient-addressed attachment envelope for the `attachment:v3`
/// cipher.  The attachment content key is never serialized in plaintext: each
/// intended device receives its own ML-KEM wrapped copy.
class PqcV3AttachmentEnvelope {
  const PqcV3AttachmentEnvelope({
    required this.attachmentId,
    required this.conversationId,
    required this.conversationType,
    required this.senderDeviceId,
    required this.senderKeysetId,
    required this.signingPublicKey,
    required this.attachment,
    required this.wraps,
    this.signature,
  });

  static const prefix = PqcV3Wire.attachmentCipherVersion;

  final String attachmentId;
  final int conversationId;
  final String conversationType;
  final String senderDeviceId;
  final String senderKeysetId;
  final String signingPublicKey;
  final PqcV3EncryptedAttachment attachment;
  final List<PqcV3RecipientWrap> wraps;
  final String? signature;

  Map<String, dynamic> toJson({bool includeSignature = true}) => {
    'protocol_version': PqcV3Wire.protocolVersion,
    'cipher_version': PqcV3Wire.attachmentCipherVersion,
    'attachment_id': attachmentId,
    'conversation_id': conversationId,
    'conversation_type': conversationType,
    'sender_device_id': senderDeviceId,
    'sender_keyset_id': senderKeysetId,
    'signing_public_key': signingPublicKey,
    'attachment': attachment.toJson(),
    'wraps': wraps.map((item) => item.toJson()).toList(),
    if (includeSignature && signature != null) 'signature': signature,
  };

  String unsignedCanonicalJson() => jsonEncode(toJson(includeSignature: false));

  String encode() =>
      '$prefix:${base64UrlEncode(utf8.encode(jsonEncode(toJson())))}';

  static PqcV3AttachmentEnvelope decode(String payload) {
    if (!payload.startsWith('$prefix:')) {
      throw const FormatException('Unsupported V3 attachment payload prefix.');
    }
    final encoded = payload.substring(prefix.length + 1);
    final padded = encoded.padRight(
      encoded.length + ((4 - encoded.length % 4) % 4),
      '=',
    );
    final decoded = jsonDecode(
      utf8.decode(base64Url.decode(padded), allowMalformed: false),
    );
    if (decoded is! Map<Object?, Object?> ||
        decoded['protocol_version'] != PqcV3Wire.protocolVersion ||
        decoded['cipher_version'] != PqcV3Wire.attachmentCipherVersion ||
        decoded['attachment'] is! Map<Object?, Object?> ||
        decoded['wraps'] is! List) {
      throw const FormatException('Invalid V3 attachment envelope.');
    }
    final parsedWraps = (decoded['wraps'] as List)
        .map((item) {
          if (item is! Map) {
            throw const FormatException(
              'V3 attachment wraps must contain objects.',
            );
          }
          return PqcV3RecipientWrap.fromJson(Map<String, dynamic>.from(item));
        })
        .toList(growable: false);
    return PqcV3AttachmentEnvelope(
      attachmentId: decoded['attachment_id'] as String? ?? '',
      conversationId: decoded['conversation_id'] as int? ?? -1,
      conversationType: decoded['conversation_type'] as String? ?? '',
      senderDeviceId: decoded['sender_device_id'] as String? ?? '',
      senderKeysetId: decoded['sender_keyset_id'] as String? ?? '',
      signingPublicKey: decoded['signing_public_key'] as String? ?? '',
      attachment: PqcV3EncryptedAttachment.fromJson(
        Map<String, dynamic>.from(decoded['attachment'] as Map),
      ),
      wraps: parsedWraps,
      signature: decoded['signature'] as String?,
    );
  }
}

class PqcV3DecryptedAttachment {
  PqcV3DecryptedAttachment({
    required List<int> bytes,
    required this.filename,
    required this.mimeType,
  }) : bytes = Uint8List.fromList(bytes);

  final Uint8List bytes;
  final String filename;
  final String mimeType;
}

class PqcV3AttachmentCodec {
  PqcV3AttachmentCodec(this._primitives);

  final PqcPrimitiveSuite _primitives;

  Uint8List generateContentKey() => _primitives.randomBytes(32);

  Future<PqcV3EncryptedAttachment> encrypt({
    required List<int> bytes,
    required String filename,
    required String mimeType,
    required List<int> contentKey,
  }) async {
    if (filename.trim().isEmpty || mimeType.trim().isEmpty) {
      throw ArgumentError('Attachment filename and MIME type are required.');
    }
    if (contentKey.length != 32) {
      throw ArgumentError('V3 attachment content key must be 32 bytes.');
    }
    final box = await _primitives.encryptAead(
      plaintext: bytes,
      key: contentKey,
      nonce: _primitives.randomBytes(12),
      associatedData: _associatedData(filename, mimeType, bytes.length),
    );
    return PqcV3EncryptedAttachment(
      filename: filename,
      mimeType: mimeType,
      sizeBytes: bytes.length,
      ciphertext: base64Encode([...box.nonce, ...box.ciphertext, ...box.mac]),
    );
  }

  Future<Uint8List> decrypt({
    required PqcV3EncryptedAttachment attachment,
    required List<int> contentKey,
  }) async {
    attachment._validateMetadata();
    if (contentKey.length != 32) {
      throw ArgumentError('V3 attachment content key must be 32 bytes.');
    }
    final packed = base64Decode(attachment.ciphertext);
    if (packed.length < 28) {
      throw const FormatException('V3 attachment ciphertext is too short.');
    }
    final clear = await _primitives.decryptAead(
      box: PqcAeadBox(
        nonce: packed.sublist(0, 12),
        ciphertext: packed.sublist(12, packed.length - 16),
        mac: packed.sublist(packed.length - 16),
      ),
      key: contentKey,
      associatedData: _associatedData(
        attachment.filename,
        attachment.mimeType,
        attachment.sizeBytes,
      ),
    );
    if (clear.length != attachment.sizeBytes) {
      throw const FormatException('V3 attachment plaintext size mismatch.');
    }
    return clear;
  }

  /// Encrypts attachment bytes and authenticates a per-device key envelope.
  /// The host supplies the current active devices for its conversation.
  Future<String> encryptForRecipients({
    required String attachmentId,
    required PqcConversation conversation,
    required List<int> bytes,
    required String filename,
    required String mimeType,
    required PqcDeviceKeyset sender,
    required Iterable<PqcDevicePublicKey> recipientDevices,
  }) async {
    if (attachmentId.trim().isEmpty) {
      throw ArgumentError.value(
        attachmentId,
        'attachmentId',
        'Must not be empty.',
      );
    }
    final recipients = _uniqueRecipients(recipientDevices, sender.publicKey);
    final contentKey = generateContentKey();
    final attachment = await encrypt(
      bytes: bytes,
      filename: filename,
      mimeType: mimeType,
      contentKey: contentKey,
    );
    final wraps = <PqcV3RecipientWrap>[];
    for (final recipient in recipients) {
      final kem = _primitives.encapsulate(recipient.kemPublicKeyBase64);
      final box = await _primitives.encryptAead(
        plaintext: contentKey,
        key: kem.sharedSecret,
        nonce: _primitives.randomBytes(12),
        associatedData: utf8.encode('$attachmentId:${recipient.deviceId}'),
      );
      wraps.add(
        PqcV3RecipientWrap(
          deviceId: recipient.deviceId,
          keysetId: recipient.keysetId,
          kemCiphertext: kem.ciphertextBase64,
          wrappedKey: base64Encode([
            ...box.nonce,
            ...box.ciphertext,
            ...box.mac,
          ]),
        ),
      );
    }
    final unsigned = PqcV3AttachmentEnvelope(
      attachmentId: attachmentId,
      conversationId: conversation.id,
      conversationType: conversation.type,
      senderDeviceId: sender.deviceId,
      senderKeysetId: sender.keysetId,
      signingPublicKey: sender.signingPublicKeyBase64,
      attachment: attachment,
      wraps: wraps,
    );
    final signature = _primitives.sign(
      message: utf8.encode(unsigned.unsignedCanonicalJson()),
      secretKeyBase64: sender.signingSecretKeyBase64,
    );
    return PqcV3AttachmentEnvelope(
      attachmentId: attachmentId,
      conversationId: conversation.id,
      conversationType: conversation.type,
      senderDeviceId: sender.deviceId,
      senderKeysetId: sender.keysetId,
      signingPublicKey: sender.signingPublicKeyBase64,
      attachment: attachment,
      wraps: wraps,
      signature: signature,
    ).encode();
  }

  /// Resolves the recipient key wrap, verifies the sender before decrypting,
  /// and returns bytes only when both metadata and content authenticate.
  Future<PqcV3DecryptedAttachment> decryptForRecipient({
    required PqcConversation conversation,
    required String payload,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    final envelope = PqcV3AttachmentEnvelope.decode(payload);
    if (envelope.attachmentId.isEmpty ||
        envelope.conversationId != conversation.id ||
        envelope.conversationType != conversation.type ||
        envelope.senderDeviceId.isEmpty ||
        envelope.senderKeysetId.isEmpty ||
        envelope.signingPublicKey.isEmpty ||
        envelope.signature == null) {
      throw const FormatException('V3 attachment context mismatch.');
    }
    final trusted = trustedSigningKeysByDevice[envelope.senderDeviceId];
    if (trusted == null || !trusted.contains(envelope.signingPublicKey)) {
      throw const FormatException('V3 attachment sender is not trusted.');
    }
    if (!_primitives.verify(
      message: utf8.encode(envelope.unsignedCanonicalJson()),
      signatureBase64: envelope.signature!,
      publicKeyBase64: envelope.signingPublicKey,
    )) {
      throw const FormatException(
        'V3 attachment signature verification failed.',
      );
    }
    final wraps = <String>{};
    for (final wrap in envelope.wraps) {
      final id = '${wrap.deviceId}|${wrap.keysetId}';
      if (wrap.deviceId.isEmpty ||
          wrap.keysetId.isEmpty ||
          wrap.kemCiphertext.isEmpty ||
          wrap.wrappedKey.isEmpty ||
          !wraps.add(id)) {
        throw const FormatException('Invalid V3 attachment recipient wrap.');
      }
    }
    PqcDeviceKeyset? selectedKeyset;
    PqcV3RecipientWrap? selectedWrap;
    for (final keyset in localKeysets) {
      for (final wrap in envelope.wraps) {
        if (wrap.deviceId == keyset.deviceId &&
            wrap.keysetId == keyset.keysetId) {
          selectedKeyset = keyset;
          selectedWrap = wrap;
          break;
        }
      }
      if (selectedWrap != null) break;
    }
    if (selectedKeyset == null || selectedWrap == null) {
      throw const PqcV3AttachmentKeyMissingException();
    }
    final packedWrap = base64Decode(selectedWrap.wrappedKey);
    if (packedWrap.length < 28) {
      throw const FormatException('V3 attachment key wrap is too short.');
    }
    final sharedSecret = _primitives.decapsulate(
      ciphertextBase64: selectedWrap.kemCiphertext,
      secretKeyBase64: selectedKeyset.kemSecretKeyBase64,
    );
    final contentKey = await _primitives.decryptAead(
      box: PqcAeadBox(
        nonce: packedWrap.sublist(0, 12),
        ciphertext: packedWrap.sublist(12, packedWrap.length - 16),
        mac: packedWrap.sublist(packedWrap.length - 16),
      ),
      key: sharedSecret,
      associatedData: utf8.encode(
        '${envelope.attachmentId}:${selectedKeyset.deviceId}',
      ),
    );
    final bytes = await decrypt(
      attachment: envelope.attachment,
      contentKey: contentKey,
    );
    return PqcV3DecryptedAttachment(
      bytes: bytes,
      filename: envelope.attachment.filename,
      mimeType: envelope.attachment.mimeType,
    );
  }

  List<int> _associatedData(String filename, String mimeType, int sizeBytes) =>
      utf8.encode('$filename|$mimeType|$sizeBytes');

  List<PqcDevicePublicKey> _uniqueRecipients(
    Iterable<PqcDevicePublicKey> supplied,
    PqcDevicePublicKey sender,
  ) {
    final recipients = <String, PqcDevicePublicKey>{};
    void add(PqcDevicePublicKey recipient) {
      if (recipient.deviceId.trim().isEmpty ||
          recipient.kemPublicKeyBase64.trim().isEmpty) {
        throw ArgumentError(
          'Every V3 attachment recipient needs a device id and ML-KEM key.',
        );
      }
      final token = '${recipient.deviceId}|${recipient.keysetId}';
      final previous = recipients[token];
      if (previous != null &&
          previous.kemPublicKeyBase64 != recipient.kemPublicKeyBase64) {
        throw StateError(
          'Conflicting attachment recipient keysets for ${recipient.deviceId}.',
        );
      }
      recipients[token] = recipient;
    }

    for (final recipient in supplied) {
      add(recipient);
    }
    add(sender);
    return recipients.values.toList(growable: false);
  }
}

class PqcV3AttachmentKeyMissingException implements Exception {
  const PqcV3AttachmentKeyMissingException();

  @override
  String toString() => 'PqcV3AttachmentKeyMissingException';
}
