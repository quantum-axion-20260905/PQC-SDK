import 'dart:convert';

import 'models.dart';
import 'primitives.dart';
import 'v2_authenticated_group_codec.dart';

class PqcV2GroupCodec {
  PqcV2GroupCodec(this._primitives)
    : _authenticated = PqcV2AuthenticatedGroupCodec(
        _primitives,
        prefix: PqcV2Wire.groupPrefix,
        algorithm: PqcV2Wire.groupAlgorithm,
      );

  final PqcPrimitiveSuite _primitives;
  final PqcV2AuthenticatedGroupCodec _authenticated;

  PqcGroupPayloadMetadata? inspect(String payload) {
    try {
      if (!payload.startsWith('${PqcV2Wire.groupPrefix}:')) {
        return null;
      }
      final document = _decode(
        payload.substring(PqcV2Wire.groupPrefix.length + 1),
      );
      if (document['protocol_version'] != PqcV2Wire.protocolVersion ||
          (document['algorithm'] != PqcV2Wire.groupAlgorithm &&
              document['algorithm'] != PqcV2Wire.legacyGroupAlgorithm)) {
        return null;
      }
      final conversationId = document['conversation_id'];
      final conversationType = document['conversation_type'];
      final epochId = document['group_epoch_id'];
      if (conversationId is! int ||
          conversationType is! String ||
          epochId is! String ||
          epochId.isEmpty) {
        return null;
      }
      return PqcGroupPayloadMetadata(
        conversationId: conversationId,
        conversationType: conversationType,
        epochId: epochId,
      );
    } catch (_) {
      return null;
    }
  }

  Future<String> encrypt({
    required PqcConversation conversation,
    required String plaintext,
    required PqcGroupEpoch epoch,
    required PqcDeviceKeyset sender,
  }) => _authenticated.encrypt(
    conversation: conversation,
    plaintext: plaintext,
    epoch: epoch,
    sender: sender,
  );

  Future<PqcDecodeResult> decrypt({
    required PqcConversation conversation,
    required String payload,
    required Map<String, PqcGroupEpoch> epochsById,
    Map<String, Set<String>> trustedSigningKeysByDevice = const {},
  }) async {
    if (!payload.startsWith('${PqcV2Wire.groupPrefix}:')) {
      return const PqcDecodeError(PqcDecodeFailure.unsupported);
    }
    try {
      final document = _decode(
        payload.substring(PqcV2Wire.groupPrefix.length + 1),
      );
      if (document['protocol_version'] != PqcV2Wire.protocolVersion ||
          (document['algorithm'] != PqcV2Wire.groupAlgorithm &&
              document['algorithm'] != PqcV2Wire.legacyGroupAlgorithm)) {
        return const PqcDecodeError(PqcDecodeFailure.corrupted);
      }
      if (document['algorithm'] == PqcV2Wire.groupAlgorithm) {
        return await _authenticated.decrypt(
          conversation: conversation,
          payload: payload,
          epochsById: epochsById,
          trustedSigningKeysByDevice: trustedSigningKeysByDevice,
        );
      }
      if (document['conversation_id'] != conversation.id ||
          document['conversation_type'] != conversation.type ||
          !conversation.isGroup) {
        return const PqcDecodeError(PqcDecodeFailure.bindingMismatch);
      }
      final epochId = document['group_epoch_id'] as String? ?? '';
      final epoch = epochsById[epochId];
      if (epoch == null) {
        return const PqcDecodeError(PqcDecodeFailure.keyMissing);
      }
      _validateEpoch(conversation, epoch);
      final clear = await _primitives.decryptAead(
        box: PqcAeadBox(
          nonce: base64Decode(document['nonce'] as String),
          ciphertext: base64Decode(document['ciphertext'] as String),
          mac: base64Decode(document['mac'] as String),
        ),
        key: epoch.secretKeyBytes,
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

  Future<String> wrapEpoch({
    required PqcConversation conversation,
    required PqcGroupEpoch epoch,
    required PqcDeviceKeyset sender,
    required PqcDevicePublicKey recipient,
  }) async {
    _validateEpoch(conversation, epoch);
    if (sender.deviceId.contains(':') || recipient.deviceId.contains(':')) {
      // The frozen V2 group-wrap format is colon-delimited. Reject ambiguous
      // identities rather than emitting a payload that cannot be parsed back.
      throw ArgumentError('V2 group-wrap device ids must not contain ":".');
    }
    final kem = _primitives.encapsulate(recipient.kemPublicKeyBase64);
    final key = await _deriveWrapKey(
      sharedSecret: kem.sharedSecret,
      conversation: conversation,
      epochId: epoch.epochId,
      senderDeviceId: sender.deviceId,
      targetDeviceId: recipient.deviceId,
    );
    final box = await _primitives.encryptAead(
      plaintext: epoch.secretKeyBytes,
      key: key,
      nonce: _primitives.randomBytes(12),
    );
    final parts = [
      sender.deviceId,
      sender.signingPublicKeyBase64,
      kem.ciphertextBase64,
      base64Encode(box.nonce),
      base64Encode(box.ciphertext),
      base64Encode(box.mac),
    ];
    final signed = [PqcV2Wire.groupWrapPrefix, ...parts].join(':').codeUnits;
    final signature = _primitives.sign(
      message: signed,
      secretKeyBase64: sender.signingSecretKeyBase64,
    );
    return [PqcV2Wire.groupWrapPrefix, ...parts, signature].join(':');
  }

  Future<PqcGroupEpoch?> unwrapEpoch({
    required PqcConversation conversation,
    required String epochId,
    required String wrappedEpoch,
    required PqcDeviceKeyset recipient,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    try {
      if (!conversation.isGroup ||
          !wrappedEpoch.startsWith('${PqcV2Wire.groupWrapPrefix}:')) {
        return null;
      }
      final parts = wrappedEpoch
          .substring(PqcV2Wire.groupWrapPrefix.length + 1)
          .split(':');
      if (parts.length != 7) {
        return null;
      }
      final senderDeviceId = parts[0];
      final signingPublicKey = parts[1];
      final trusted = trustedSigningKeysByDevice[senderDeviceId];
      if (trusted == null || !trusted.contains(signingPublicKey)) {
        return null;
      }
      final signed = [
        PqcV2Wire.groupWrapPrefix,
        ...parts.sublist(0, 6),
      ].join(':').codeUnits;
      if (!_primitives.verify(
        message: signed,
        signatureBase64: parts[6],
        publicKeyBase64: signingPublicKey,
      )) {
        return null;
      }
      final sharedSecret = _primitives.decapsulate(
        ciphertextBase64: parts[2],
        secretKeyBase64: recipient.kemSecretKeyBase64,
      );
      final key = await _deriveWrapKey(
        sharedSecret: sharedSecret,
        conversation: conversation,
        epochId: epochId,
        senderDeviceId: senderDeviceId,
        targetDeviceId: recipient.deviceId,
      );
      final clear = await _primitives.decryptAead(
        box: PqcAeadBox(
          nonce: base64Decode(parts[3]),
          ciphertext: base64Decode(parts[4]),
          mac: base64Decode(parts[5]),
        ),
        key: key,
      );
      if (clear.length != 32) {
        return null;
      }
      return PqcGroupEpoch(epochId: epochId, secretKeyBytes: clear);
    } catch (_) {
      return null;
    }
  }

  Future<List<int>> _deriveWrapKey({
    required List<int> sharedSecret,
    required PqcConversation conversation,
    required String epochId,
    required String senderDeviceId,
    required String targetDeviceId,
  }) {
    return _primitives.deriveKey(
      secret: sharedSecret,
      nonce: utf8.encode(
        '${conversation.id}|$epochId|$senderDeviceId|$targetDeviceId',
      ),
      info: utf8.encode('pqc-chat-group-key-wrap-v1'),
    );
  }

  void _validateEpoch(PqcConversation conversation, PqcGroupEpoch epoch) {
    if (!conversation.isGroup) {
      throw ArgumentError('Group codec requires a group conversation.');
    }
    if (epoch.epochId.isEmpty || epoch.secretKeyBytes.length != 32) {
      throw ArgumentError('Group epoch id and 32-byte key are required.');
    }
  }
}

Map<String, dynamic> _decode(String encoded) {
  final padded = encoded.padRight(
    encoded.length + ((4 - encoded.length % 4) % 4),
    '=',
  );
  final value = jsonDecode(
    utf8.decode(base64Url.decode(padded), allowMalformed: false),
  );
  if (value is! Map<String, dynamic>) {
    throw const FormatException('Group payload must be an object.');
  }
  return Map<String, dynamic>.from(value);
}
