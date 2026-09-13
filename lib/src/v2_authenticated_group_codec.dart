import 'dart:convert';

import 'models.dart';
import 'primitives.dart';

/// Authenticated V2 group-message codec.
///
/// The codec is parameterized by its prefix so the production `group:v2`
/// writer and the transitional `group:v2-auth` alias share exactly the same
/// authenticated implementation. The old unauthenticated V2 format is
/// decoded by [PqcV2GroupCodec] only as legacy history.
class PqcV2AuthenticatedGroupCodec {
  PqcV2AuthenticatedGroupCodec(
    this._primitives, {
    this.prefix = PqcV2Wire.authenticatedGroupPrefix,
    this.algorithm = PqcV2Wire.authenticatedGroupAlgorithm,
  });

  final PqcPrimitiveSuite _primitives;
  final String prefix;
  final String algorithm;

  PqcGroupPayloadMetadata? inspect(String payload) {
    try {
      if (!payload.startsWith('$prefix:')) {
        return null;
      }
      final document = _decode(payload.substring(prefix.length + 1));
      if (document['protocol_version'] != PqcV2Wire.protocolVersion ||
          document['algorithm'] != algorithm) {
        return null;
      }
      final conversationId = document['conversation_id'];
      final conversationType = document['conversation_type'];
      final epochId = document['group_epoch_id'];
      if (conversationId is! int ||
          conversationId <= 0 ||
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
  }) async {
    _validate(conversation, epoch, sender);
    final associatedData = _associatedData(
      conversation: conversation,
      epochId: epoch.epochId,
      senderDeviceId: sender.deviceId,
      senderKeysetId: sender.keysetId,
      signingPublicKey: sender.signingPublicKeyBase64,
    );
    final box = await _primitives.encryptAead(
      plaintext: utf8.encode(plaintext),
      key: epoch.secretKeyBytes,
      nonce: _primitives.randomBytes(12),
      associatedData: associatedData,
    );
    final unsigned = <String, dynamic>{
      'protocol_version': PqcV2Wire.protocolVersion,
      'algorithm': algorithm,
      'conversation_id': conversation.id,
      'conversation_type': conversation.type,
      'group_epoch_id': epoch.epochId,
      'sender_device_id': sender.deviceId,
      'sender_keyset_id': sender.keysetId,
      'signing_public_key': sender.signingPublicKeyBase64,
      'nonce': base64Encode(box.nonce),
      'ciphertext': base64Encode(box.ciphertext),
      'mac': base64Encode(box.mac),
    };
    final signature = _primitives.sign(
      message: utf8.encode(jsonEncode(unsigned)),
      secretKeyBase64: sender.signingSecretKeyBase64,
    );
    return '$prefix:${_encode({...unsigned, 'signature': signature})}';
  }

  Future<PqcDecodeResult> decrypt({
    required PqcConversation conversation,
    required String payload,
    required Map<String, PqcGroupEpoch> epochsById,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    if (!payload.startsWith('$prefix:')) {
      return const PqcDecodeError(PqcDecodeFailure.unsupported);
    }
    try {
      final document = _decode(payload.substring(prefix.length + 1));
      if (document['protocol_version'] != PqcV2Wire.protocolVersion ||
          document['algorithm'] != algorithm) {
        return const PqcDecodeError(PqcDecodeFailure.corrupted);
      }
      if (document['conversation_id'] != conversation.id ||
          document['conversation_type'] != conversation.type ||
          !conversation.isGroup ||
          conversation.id <= 0) {
        return const PqcDecodeError(PqcDecodeFailure.bindingMismatch);
      }

      final senderDeviceId = document['sender_device_id'] as String? ?? '';
      final senderKeysetId = document['sender_keyset_id'] as String? ?? '';
      final signingPublicKey = document['signing_public_key'] as String? ?? '';
      final signature = document.remove('signature') as String? ?? '';
      if (senderDeviceId.isEmpty ||
          senderKeysetId.isEmpty ||
          signingPublicKey.isEmpty ||
          signature.isEmpty) {
        return const PqcDecodeError(PqcDecodeFailure.corrupted);
      }
      final trusted = trustedSigningKeysByDevice[senderDeviceId];
      if (trusted == null || !trusted.contains(signingPublicKey)) {
        return const PqcDecodeError(PqcDecodeFailure.untrustedSender);
      }
      if (!_primitives.verify(
        message: utf8.encode(jsonEncode(document)),
        signatureBase64: signature,
        publicKeyBase64: signingPublicKey,
      )) {
        return const PqcDecodeError(PqcDecodeFailure.corrupted);
      }

      final epochId = document['group_epoch_id'] as String? ?? '';
      final epoch = epochsById[epochId];
      if (epoch == null) {
        return const PqcDecodeError(PqcDecodeFailure.keyMissing);
      }
      _validateEpoch(conversation, epoch);
      final clear = await _primitives.decryptAead(
        box: PqcAeadBox(
          nonce: base64Decode(document['nonce'] as String? ?? ''),
          ciphertext: base64Decode(document['ciphertext'] as String? ?? ''),
          mac: base64Decode(document['mac'] as String? ?? ''),
        ),
        key: epoch.secretKeyBytes,
        associatedData: _associatedData(
          conversation: conversation,
          epochId: epochId,
          senderDeviceId: senderDeviceId,
          senderKeysetId: senderKeysetId,
          signingPublicKey: signingPublicKey,
        ),
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

  List<int> _associatedData({
    required PqcConversation conversation,
    required String epochId,
    required String senderDeviceId,
    required String senderKeysetId,
    required String signingPublicKey,
  }) => utf8.encode(
    jsonEncode({
      'protocol_version': PqcV2Wire.protocolVersion,
      'algorithm': algorithm,
      'conversation_id': conversation.id,
      'conversation_type': conversation.type,
      'group_epoch_id': epochId,
      'sender_device_id': senderDeviceId,
      'sender_keyset_id': senderKeysetId,
      'signing_public_key': signingPublicKey,
    }),
  );

  void _validate(
    PqcConversation conversation,
    PqcGroupEpoch epoch,
    PqcDeviceKeyset sender,
  ) {
    _validateEpoch(conversation, epoch);
    if (sender.deviceId.trim().isEmpty ||
        sender.signingPublicKeyBase64.trim().isEmpty ||
        sender.signingSecretKeyBase64.trim().isEmpty) {
      throw ArgumentError('Authenticated V2 group sender is incomplete.');
    }
  }

  void _validateEpoch(PqcConversation conversation, PqcGroupEpoch epoch) {
    if (!conversation.isGroup || conversation.id <= 0) {
      throw ArgumentError('Group codec requires a group conversation.');
    }
    if (epoch.epochId.isEmpty || epoch.secretKeyBytes.length != 32) {
      throw ArgumentError('Group epoch id and 32-byte key are required.');
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
  final value = jsonDecode(
    utf8.decode(base64Url.decode(padded), allowMalformed: false),
  );
  if (value is! Map<String, dynamic>) {
    throw const FormatException(
      'Authenticated group payload must be an object.',
    );
  }
  return Map<String, dynamic>.from(value);
}
