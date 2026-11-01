import 'dart:convert';

import 'models.dart';
import 'primitives.dart';

/// V2.5 candidate group-epoch envelope.
///
/// The frozen V2 envelope is intentionally left untouched. This envelope has
/// a new prefix and signs every routing and cryptographic field, including the
/// conversation, epoch, sender, recipient and keyset binding. It can therefore
/// be rolled out behind capability negotiation without making old V2 history
/// unreadable.
class PqcV25GroupEpochCodec {
  PqcV25GroupEpochCodec(this._primitives);

  final PqcPrimitiveSuite _primitives;

  Future<String> wrapEpoch({
    required PqcConversation conversation,
    required PqcGroupEpoch epoch,
    required PqcDeviceKeyset sender,
    required PqcDevicePublicKey recipient,
  }) async {
    _validateConversation(conversation);
    _validateEpoch(epoch);
    _validateDevice(
      sender.deviceId,
      sender.kemPublicKeyBase64,
      sender.signingPublicKeyBase64,
    );
    _validateDevice(
      recipient.deviceId,
      recipient.kemPublicKeyBase64,
      recipient.signingPublicKeyBase64,
    );

    final kem = _primitives.encapsulate(recipient.kemPublicKeyBase64);
    final key = await _deriveWrapKey(
      sharedSecret: kem.sharedSecret,
      conversation: conversation,
      epochId: epoch.epochId,
      senderBindingId: sender.bindingId,
      targetDeviceId: recipient.deviceId,
      targetBindingId: recipient.bindingId,
    );
    final box = await _primitives.encryptAead(
      plaintext: epoch.secretKeyBytes,
      key: key,
      nonce: _primitives.randomBytes(12),
    );
    final unsigned = <String, dynamic>{
      'protocol_version': PqcV2Wire.protocolVersion,
      'algorithm': PqcV2Wire.groupEnvelopeV25Algorithm,
      'conversation_id': conversation.id,
      'conversation_type': conversation.type,
      'epoch_id': epoch.epochId,
      'sender_device_id': sender.deviceId,
      'sender_keyset_id': sender.bindingId,
      'target_device_id': recipient.deviceId,
      'target_keyset_id': recipient.bindingId,
      'signing_public_key': sender.signingPublicKeyBase64,
      'kem_ciphertext': kem.ciphertextBase64,
      'nonce': base64Encode(box.nonce),
      'ciphertext': base64Encode(box.ciphertext),
      'mac': base64Encode(box.mac),
    };
    final signature = _primitives.sign(
      message: utf8.encode(jsonEncode(unsigned)),
      secretKeyBase64: sender.signingSecretKeyBase64,
    );
    return '${PqcV2Wire.groupWrapV25Prefix}:${_encode({...unsigned, 'signature': signature})}';
  }

  Future<PqcGroupEpoch?> unwrapEpoch({
    required PqcConversation conversation,
    required String wrappedEpoch,
    required PqcDeviceKeyset recipient,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
    required Map<String, Set<String>> trustedKeysetBindingsByDevice,
  }) async {
    try {
      _validateConversation(conversation);
      _validateDevice(
        recipient.deviceId,
        recipient.kemPublicKeyBase64,
        recipient.signingPublicKeyBase64,
      );
      if (!wrappedEpoch.startsWith('${PqcV2Wire.groupWrapV25Prefix}:')) {
        return null;
      }
      final document = _decode(
        wrappedEpoch.substring(PqcV2Wire.groupWrapV25Prefix.length + 1),
      );
      if (document['protocol_version'] != PqcV2Wire.protocolVersion ||
          document['algorithm'] != PqcV2Wire.groupEnvelopeV25Algorithm ||
          document['conversation_id'] != conversation.id ||
          document['conversation_type'] != conversation.type) {
        return null;
      }

      final epochId = document['epoch_id'] as String? ?? '';
      final senderDeviceId = document['sender_device_id'] as String? ?? '';
      final senderBindingId = document['sender_keyset_id'] as String? ?? '';
      final targetDeviceId = document['target_device_id'] as String? ?? '';
      final targetBindingId = document['target_keyset_id'] as String? ?? '';
      final signingPublicKey = document['signing_public_key'] as String? ?? '';
      final signature = document['signature'] as String? ?? '';
      if (epochId.isEmpty ||
          senderDeviceId.isEmpty ||
          senderBindingId.isEmpty ||
          targetDeviceId != recipient.deviceId ||
          targetBindingId != recipient.bindingId ||
          signingPublicKey.isEmpty ||
          signature.isEmpty) {
        return null;
      }
      final trustedKeys = trustedSigningKeysByDevice[senderDeviceId];
      if (trustedKeys == null || !trustedKeys.contains(signingPublicKey)) {
        return null;
      }
      final trustedBindings = trustedKeysetBindingsByDevice[senderDeviceId];
      if (trustedBindings == null ||
          !trustedBindings.contains(senderBindingId)) {
        return null;
      }

      final unsigned = Map<String, dynamic>.from(document)..remove('signature');
      if (!_primitives.verify(
        message: utf8.encode(jsonEncode(unsigned)),
        signatureBase64: signature,
        publicKeyBase64: signingPublicKey,
      )) {
        return null;
      }
      final sharedSecret = _primitives.decapsulate(
        ciphertextBase64: document['kem_ciphertext'] as String? ?? '',
        secretKeyBase64: recipient.kemSecretKeyBase64,
      );
      final key = await _deriveWrapKey(
        sharedSecret: sharedSecret,
        conversation: conversation,
        epochId: epochId,
        senderBindingId: senderBindingId,
        targetDeviceId: recipient.deviceId,
        targetBindingId: recipient.bindingId,
      );
      final clear = await _primitives.decryptAead(
        box: PqcAeadBox(
          nonce: base64Decode(document['nonce'] as String),
          ciphertext: base64Decode(document['ciphertext'] as String),
          mac: base64Decode(document['mac'] as String),
        ),
        key: key,
      );
      if (clear.length != 32) return null;
      return PqcGroupEpoch(epochId: epochId, secretKeyBytes: clear);
    } catch (_) {
      return null;
    }
  }

  Future<List<int>> _deriveWrapKey({
    required List<int> sharedSecret,
    required PqcConversation conversation,
    required String epochId,
    required String senderBindingId,
    required String targetDeviceId,
    required String targetBindingId,
  }) {
    return _primitives.deriveKey(
      secret: sharedSecret,
      nonce: utf8.encode(
        jsonEncode({
          'conversation_id': conversation.id,
          'conversation_type': conversation.type,
          'epoch_id': epochId,
          'sender_keyset_id': senderBindingId,
          'target_device_id': targetDeviceId,
          'target_keyset_id': targetBindingId,
        }),
      ),
      info: utf8.encode('pqc-chat-group-key-wrap-v2.5'),
    );
  }

  void _validateConversation(PqcConversation conversation) {
    if (!conversation.isGroup) {
      throw ArgumentError(
        'Group epoch envelope requires a group conversation.',
      );
    }
  }

  void _validateEpoch(PqcGroupEpoch epoch) {
    if (epoch.epochId.isEmpty || epoch.secretKeyBytes.length != 32) {
      throw ArgumentError('Group epoch id and 32-byte key are required.');
    }
  }

  void _validateDevice(
    String deviceId,
    String kemPublicKey,
    String signingPublicKey,
  ) {
    if (deviceId.trim().isEmpty ||
        kemPublicKey.trim().isEmpty ||
        signingPublicKey.trim().isEmpty) {
      throw ArgumentError('Device id and both public keys are required.');
    }
  }
}

String _encode(Map<String, dynamic> value) =>
    base64UrlEncode(utf8.encode(jsonEncode(value))).replaceAll('=', '');

Map<String, dynamic> _decode(String encoded) {
  final padded = encoded.padRight(
    encoded.length + ((4 - encoded.length % 4) % 4),
    '=',
  );
  final value = jsonDecode(utf8.decode(base64Url.decode(padded)));
  if (value is! Map<String, dynamic>) {
    throw const FormatException('Group epoch envelope must be an object.');
  }
  return Map<String, dynamic>.from(value);
}
