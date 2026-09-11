import 'dart:convert';
import 'dart:typed_data';

import 'models.dart';
import 'primitives.dart';
import 'v3_envelope.dart';

/// Authenticated recipient-wrap V3 private-message codec.
///
/// Every recipient device, including the sender's own device, receives a
/// separate ML-KEM wrapped content key.  This makes sent history decryptable
/// after a reinstall once historical keysets are restored.
class PqcV3PrivateCodec {
  PqcV3PrivateCodec(PqcPrimitiveSuite primitives)
    : _codec = PqcV3MessageCodec(primitives);

  final PqcV3MessageCodec _codec;

  Future<String> encrypt({
    required PqcConversation conversation,
    required String messageId,
    required String plaintext,
    required PqcDeviceKeyset sender,
    required Iterable<PqcDevicePublicKey> recipientDevices,
  }) => _codec.encrypt(
    isGroup: false,
    conversation: conversation,
    messageId: messageId,
    plaintext: plaintext,
    sender: sender,
    recipientDevices: recipientDevices,
  );

  Future<PqcDecodeResult> decrypt({
    required PqcConversation conversation,
    required String payload,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) => _codec.decrypt(
    expectedGroup: false,
    conversation: conversation,
    payload: payload,
    localKeysets: localKeysets,
    trustedSigningKeysByDevice: trustedSigningKeysByDevice,
  );
}

/// Shared implementation used by the explicit V3 private and group facades.
/// It is public only because Dart libraries are file-scoped; applications
/// should call [PqcV3PrivateCodec] or [PqcV3GroupCodec] instead.
class PqcV3MessageCodec {
  PqcV3MessageCodec(this._primitives);

  final PqcPrimitiveSuite _primitives;

  Future<String> encrypt({
    required bool isGroup,
    required PqcConversation conversation,
    required String messageId,
    required String plaintext,
    required PqcDeviceKeyset sender,
    required Iterable<PqcDevicePublicKey> recipientDevices,
  }) async {
    if (conversation.isGroup != isGroup) {
      throw ArgumentError('Conversation kind does not match the V3 codec.');
    }
    if (messageId.trim().isEmpty) {
      throw ArgumentError.value(messageId, 'messageId', 'Must not be empty.');
    }
    final recipients = _uniqueRecipients(recipientDevices, sender.publicKey);
    final contentKey = _primitives.randomBytes(32);
    final encrypted = await _encryptPacked(
      plaintext: utf8.encode(plaintext),
      contentKey: contentKey,
      associatedData: _associatedData(
        conversation: conversation,
        messageId: messageId,
        senderDeviceId: sender.deviceId,
        senderKeysetId: sender.keysetId,
      ),
    );
    final wraps = <PqcV3RecipientWrap>[];
    for (final recipient in recipients) {
      final kem = _primitives.encapsulate(recipient.kemPublicKeyBase64);
      final wrapped = await _encryptPacked(
        plaintext: contentKey,
        contentKey: kem.sharedSecret,
        associatedData: utf8.encode('$messageId:${recipient.deviceId}'),
      );
      wraps.add(
        PqcV3RecipientWrap(
          deviceId: recipient.deviceId,
          keysetId: recipient.keysetId,
          kemCiphertext: kem.ciphertextBase64,
          wrappedKey: base64Encode(wrapped),
        ),
      );
    }
    final unsigned = PqcV3Envelope(
      isGroup: isGroup,
      messageId: messageId,
      senderDeviceId: sender.deviceId,
      keysetId: sender.keysetId,
      ciphertext: base64Encode(encrypted),
      conversationId: conversation.id,
      conversationType: conversation.type,
      senderKeysetId: sender.keysetId,
      signingPublicKey: sender.signingPublicKeyBase64,
      wraps: wraps,
    );
    final signature = _primitives.sign(
      message: utf8.encode(unsigned.unsignedCanonicalJson()),
      secretKeyBase64: sender.signingSecretKeyBase64,
    );
    return PqcV3Envelope(
      isGroup: isGroup,
      messageId: messageId,
      senderDeviceId: sender.deviceId,
      keysetId: sender.keysetId,
      ciphertext: base64Encode(encrypted),
      conversationId: conversation.id,
      conversationType: conversation.type,
      senderKeysetId: sender.keysetId,
      signingPublicKey: sender.signingPublicKeyBase64,
      wraps: wraps,
      signature: signature,
    ).encode();
  }

  Future<PqcDecodeResult> decrypt({
    required bool expectedGroup,
    required PqcConversation conversation,
    required String payload,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    final expectedPrefix = expectedGroup
        ? PqcV3Wire.groupPrefix
        : PqcV3Wire.privatePrefix;
    if (!payload.startsWith('$expectedPrefix:')) {
      return const PqcDecodeError(PqcDecodeFailure.unsupported);
    }
    try {
      final envelope = PqcV3Envelope.decode(payload);
      if (envelope.isGroup != expectedGroup ||
          conversation.isGroup != expectedGroup ||
          envelope.messageId.isEmpty ||
          envelope.senderDeviceId.isEmpty ||
          envelope.keysetId.isEmpty ||
          envelope.ciphertext.isEmpty ||
          envelope.conversationId != conversation.id ||
          envelope.conversationType != conversation.type ||
          envelope.senderKeysetId != envelope.keysetId) {
        return const PqcDecodeError(PqcDecodeFailure.bindingMismatch);
      }
      final signingPublicKey = envelope.signingPublicKey;
      final signature = envelope.signature;
      final trusted = trustedSigningKeysByDevice[envelope.senderDeviceId];
      if (signingPublicKey == null ||
          signature == null ||
          trusted == null ||
          !trusted.contains(signingPublicKey)) {
        return const PqcDecodeError(PqcDecodeFailure.untrustedSender);
      }
      if (!_primitives.verify(
        message: utf8.encode(envelope.unsignedCanonicalJson()),
        signatureBase64: signature,
        publicKeyBase64: signingPublicKey,
      )) {
        return const PqcDecodeError(PqcDecodeFailure.corrupted);
      }
      final seenRecipients = <String>{};
      for (final wrap in envelope.wraps) {
        final id = '${wrap.deviceId}|${wrap.keysetId}';
        if (wrap.deviceId.isEmpty ||
            wrap.keysetId.isEmpty ||
            wrap.kemCiphertext.isEmpty ||
            wrap.wrappedKey.isEmpty ||
            !seenRecipients.add(id)) {
          return const PqcDecodeError(PqcDecodeFailure.corrupted);
        }
      }
      if (envelope.wraps.isEmpty) {
        return const PqcDecodeError(PqcDecodeFailure.keyMissing);
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
        return const PqcDecodeError(PqcDecodeFailure.keyMissing);
      }
      final sharedSecret = _primitives.decapsulate(
        ciphertextBase64: selectedWrap.kemCiphertext,
        secretKeyBase64: selectedKeyset.kemSecretKeyBase64,
      );
      final contentKey = await _decryptPacked(
        ciphertext: base64Decode(selectedWrap.wrappedKey),
        contentKey: sharedSecret,
        associatedData: utf8.encode(
          '${envelope.messageId}:${selectedKeyset.deviceId}',
        ),
      );
      final clear = await _decryptPacked(
        ciphertext: base64Decode(envelope.ciphertext),
        contentKey: contentKey,
        associatedData: _associatedData(
          conversation: conversation,
          messageId: envelope.messageId,
          senderDeviceId: envelope.senderDeviceId,
          senderKeysetId: envelope.senderKeysetId!,
        ),
      );
      return PqcDecoded(
        plaintext: utf8.decode(clear, allowMalformed: false),
        protocolVersion: PqcV3Wire.protocolVersion,
      );
    } catch (error) {
      return PqcDecodeError(
        PqcDecodeFailure.corrupted,
        details: error.runtimeType.toString(),
      );
    }
  }

  List<PqcDevicePublicKey> _uniqueRecipients(
    Iterable<PqcDevicePublicKey> supplied,
    PqcDevicePublicKey sender,
  ) {
    final recipients = <String, PqcDevicePublicKey>{};
    void add(PqcDevicePublicKey recipient) {
      if (recipient.deviceId.trim().isEmpty ||
          recipient.kemPublicKeyBase64.trim().isEmpty) {
        throw ArgumentError(
          'Every V3 recipient needs a device id and ML-KEM key.',
        );
      }
      final token = '${recipient.deviceId}|${recipient.keysetId}';
      final previous = recipients[token];
      if (previous != null &&
          previous.kemPublicKeyBase64 != recipient.kemPublicKeyBase64) {
        throw StateError(
          'Conflicting recipient keysets for ${recipient.deviceId}.',
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

  Future<Uint8List> _decryptPacked({
    required List<int> ciphertext,
    required List<int> contentKey,
    required List<int> associatedData,
  }) {
    if (ciphertext.length < 28) {
      throw const FormatException('V3 AES-GCM ciphertext is too short.');
    }
    return _primitives.decryptAead(
      box: PqcAeadBox(
        nonce: ciphertext.sublist(0, 12),
        ciphertext: ciphertext.sublist(12, ciphertext.length - 16),
        mac: ciphertext.sublist(ciphertext.length - 16),
      ),
      key: contentKey,
      associatedData: associatedData,
    );
  }

  Future<Uint8List> _encryptPacked({
    required List<int> plaintext,
    required List<int> contentKey,
    required List<int> associatedData,
  }) async {
    final box = await _primitives.encryptAead(
      plaintext: plaintext,
      key: contentKey,
      nonce: _primitives.randomBytes(12),
      associatedData: associatedData,
    );
    return Uint8List.fromList([...box.nonce, ...box.ciphertext, ...box.mac]);
  }

  List<int> _associatedData({
    required PqcConversation conversation,
    required String messageId,
    required String senderDeviceId,
    required String senderKeysetId,
  }) => utf8.encode(
    jsonEncode({
      'conversation_id': conversation.id,
      'conversation_type': conversation.type,
      'message_id': messageId,
      'sender_device_id': senderDeviceId,
      'keyset_id': senderKeysetId,
    }),
  );
}
