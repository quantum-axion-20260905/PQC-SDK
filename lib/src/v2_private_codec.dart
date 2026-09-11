import 'dart:convert';
import 'dart:typed_data';

import 'models.dart';
import 'primitives.dart';

class PqcV2PrivateCodec {
  PqcV2PrivateCodec(this._primitives);

  final PqcPrimitiveSuite _primitives;

  Future<String> encrypt({
    required PqcConversation conversation,
    required String plaintext,
    required PqcDeviceKeyset sender,
    required Iterable<PqcDevicePublicKey> recipientDevices,
  }) async {
    if (conversation.isGroup) {
      throw ArgumentError('Private codec cannot write a group conversation.');
    }
    final recipients = <String, PqcDevicePublicKey>{};
    for (final device in recipientDevices) {
      if (device.deviceId.isEmpty || device.kemPublicKeyBase64.isEmpty) {
        throw ArgumentError(
          'Every recipient needs a device id and ML-KEM key.',
        );
      }
      final existing = recipients[device.deviceId];
      if (existing != null &&
          existing.kemPublicKeyBase64 != device.kemPublicKeyBase64) {
        throw StateError(
          'Conflicting active keysets for device ${device.deviceId}.',
        );
      }
      recipients[device.deviceId] = device;
    }
    recipients.putIfAbsent(sender.deviceId, () => sender.publicKey);
    if (recipients.isEmpty) {
      throw StateError('At least one recipient device is required.');
    }

    final contentKey = _primitives.randomBytes(32);
    final contentBox = await _primitives.encryptAead(
      plaintext: utf8.encode(plaintext),
      key: contentKey,
      nonce: _primitives.randomBytes(12),
    );
    final wraps = <Map<String, String>>[];
    for (final device in recipients.values) {
      final kem = _primitives.encapsulate(device.kemPublicKeyBase64);
      final wrapKey = await _deriveWrapKey(
        sharedSecret: kem.sharedSecret,
        conversation: conversation,
        senderDeviceId: sender.deviceId,
        targetDeviceId: device.deviceId,
      );
      final wrapBox = await _primitives.encryptAead(
        plaintext: contentKey,
        key: wrapKey,
        nonce: _primitives.randomBytes(12),
      );
      wraps.add({
        'target_device_id': device.deviceId,
        'target_keyset_id': device.keysetId,
        'kem_ciphertext': kem.ciphertextBase64,
        'nonce': base64Encode(wrapBox.nonce),
        'ciphertext': base64Encode(wrapBox.ciphertext),
        'mac': base64Encode(wrapBox.mac),
      });
    }

    final unsigned = <String, dynamic>{
      'protocol_version': PqcV2Wire.protocolVersion,
      'algorithm': PqcV2Wire.privateAlgorithm,
      'conversation_id': conversation.id,
      'conversation_type': conversation.type,
      'sender_device_id': sender.deviceId,
      'sender_keyset_id': sender.keysetId,
      'signing_public_key': sender.signingPublicKeyBase64,
      'content_nonce': base64Encode(contentBox.nonce),
      'content_ciphertext': base64Encode(contentBox.ciphertext),
      'content_mac': base64Encode(contentBox.mac),
      'wraps': wraps,
    };
    final signature = _primitives.sign(
      message: utf8.encode(jsonEncode(unsigned)),
      secretKeyBase64: sender.signingSecretKeyBase64,
    );
    return '${PqcV2Wire.privatePrefix}:${_encodeDocument({...unsigned, 'signature': signature})}';
  }

  Future<PqcDecodeResult> decrypt({
    required PqcConversation conversation,
    required String payload,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    if (!payload.startsWith('${PqcV2Wire.privatePrefix}:')) {
      return const PqcDecodeError(PqcDecodeFailure.unsupported);
    }
    try {
      final document = _decodeDocument(
        payload.substring(PqcV2Wire.privatePrefix.length + 1),
      );
      if (document['protocol_version'] != PqcV2Wire.protocolVersion ||
          document['algorithm'] != PqcV2Wire.privateAlgorithm) {
        return const PqcDecodeError(PqcDecodeFailure.corrupted);
      }
      if (document['conversation_id'] != conversation.id ||
          document['conversation_type'] != conversation.type ||
          conversation.isGroup) {
        return const PqcDecodeError(PqcDecodeFailure.bindingMismatch);
      }

      final signature = document.remove('signature') as String? ?? '';
      final senderDeviceId = document['sender_device_id'] as String? ?? '';
      final signingPublicKey = document['signing_public_key'] as String? ?? '';
      final trustedKeys = trustedSigningKeysByDevice[senderDeviceId];
      if (trustedKeys == null || !trustedKeys.contains(signingPublicKey)) {
        return const PqcDecodeError(PqcDecodeFailure.untrustedSender);
      }
      if (!_primitives.verify(
        message: utf8.encode(jsonEncode(document)),
        signatureBase64: signature,
        publicKeyBase64: signingPublicKey,
      )) {
        return const PqcDecodeError(PqcDecodeFailure.corrupted);
      }

      final rawWraps = document['wraps'];
      if (rawWraps != null && rawWraps is! List) {
        return const PqcDecodeError(PqcDecodeFailure.corrupted);
      }
      final wraps = ((rawWraps as List?) ?? const [])
          .map((value) {
            if (value is! Map) {
              throw const FormatException(
                'Private recipient wraps must be maps.',
              );
            }
            return value.map(
              (key, item) => MapEntry(key.toString(), item.toString()),
            );
          })
          .toList(growable: false);
      PqcDeviceKeyset? selectedKeyset;
      Map<String, String>? selectedWrap;
      for (final keyset in localKeysets) {
        for (final wrap in wraps) {
          if (wrap['target_device_id'] == keyset.deviceId &&
              wrap['target_keyset_id'] == keyset.keysetId) {
            selectedKeyset = keyset;
            selectedWrap = wrap;
            break;
          }
        }
        if (selectedWrap != null) {
          break;
        }
      }
      if (selectedKeyset == null || selectedWrap == null) {
        return const PqcDecodeError(PqcDecodeFailure.keyMissing);
      }

      final sharedSecret = _primitives.decapsulate(
        ciphertextBase64: selectedWrap['kem_ciphertext'] ?? '',
        secretKeyBase64: selectedKeyset.kemSecretKeyBase64,
      );
      final wrapKey = await _deriveWrapKey(
        sharedSecret: sharedSecret,
        conversation: conversation,
        senderDeviceId: senderDeviceId,
        targetDeviceId: selectedKeyset.deviceId,
      );
      final contentKey = await _primitives.decryptAead(
        box: PqcAeadBox(
          nonce: base64Decode(selectedWrap['nonce'] ?? ''),
          ciphertext: base64Decode(selectedWrap['ciphertext'] ?? ''),
          mac: base64Decode(selectedWrap['mac'] ?? ''),
        ),
        key: wrapKey,
      );
      final clear = await _primitives.decryptAead(
        box: PqcAeadBox(
          nonce: base64Decode(document['content_nonce'] as String),
          ciphertext: base64Decode(document['content_ciphertext'] as String),
          mac: base64Decode(document['content_mac'] as String),
        ),
        key: contentKey,
      );
      return PqcDecoded(
        plaintext: utf8.decode(clear, allowMalformed: false),
        protocolVersion: PqcV2Wire.protocolVersion,
      );
    } catch (error) {
      return PqcDecodeError(
        PqcDecodeFailure.corrupted,
        details: error.runtimeType.toString(),
      );
    }
  }

  Future<Uint8List> _deriveWrapKey({
    required List<int> sharedSecret,
    required PqcConversation conversation,
    required String senderDeviceId,
    required String targetDeviceId,
  }) {
    return _primitives.deriveKey(
      secret: sharedSecret,
      nonce: utf8.encode(
        '${conversation.id}|${conversation.type}|$senderDeviceId|$targetDeviceId',
      ),
      info: utf8.encode('pqc-chat-private-wrap-v1'),
    );
  }
}

String _encodeDocument(Map<String, dynamic> document) {
  return base64UrlEncode(utf8.encode(jsonEncode(document))).replaceAll('=', '');
}

Map<String, dynamic> _decodeDocument(String encoded) {
  final padded = encoded.padRight(
    encoded.length + ((4 - encoded.length % 4) % 4),
    '=',
  );
  final value = jsonDecode(
    utf8.decode(base64Url.decode(padded), allowMalformed: false),
  );
  if (value is! Map<String, dynamic>) {
    throw const FormatException('Payload document must be an object.');
  }
  return Map<String, dynamic>.from(value);
}
