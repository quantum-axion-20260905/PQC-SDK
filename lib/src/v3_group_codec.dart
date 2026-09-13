import 'models.dart';
import 'primitives.dart';
import 'v3_envelope.dart';
import 'v3_private_codec.dart';

/// V3 group codec using a fresh message key and a recipient-device ML-KEM wrap
/// for every active group member device.  This is deliberately separate from
/// V2 group epochs: a V3 envelope is self-contained and a member/keyset change
/// cannot make an old payload bind to a different group epoch.
class PqcV3GroupCodec {
  PqcV3GroupCodec(PqcPrimitiveSuite primitives)
    : _codec = PqcV3MessageCodec(primitives);

  final PqcV3MessageCodec _codec;

  Future<String> encrypt({
    required PqcConversation conversation,
    required String messageId,
    required String plaintext,
    required PqcDeviceKeyset sender,
    required Iterable<PqcDevicePublicKey> memberDevices,
    Iterable<PqcDevicePublicKey>? expectedMemberDevices,
  }) {
    if (expectedMemberDevices != null) {
      _assertCoverage(
        actual: memberDevices,
        expected: expectedMemberDevices,
        sender: sender.publicKey,
      );
    }
    return _codec.encrypt(
      isGroup: true,
      conversation: conversation,
      messageId: messageId,
      plaintext: plaintext,
      sender: sender,
      recipientDevices: memberDevices,
    );
  }

  Future<PqcDecodeResult> decrypt({
    required PqcConversation conversation,
    required String payload,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) => _codec.decrypt(
    expectedGroup: true,
    conversation: conversation,
    payload: payload,
    localKeysets: localKeysets,
    trustedSigningKeysByDevice: trustedSigningKeysByDevice,
  );

  /// V3 carries recipient wraps rather than a V2 group epoch identifier.  The
  /// returned metadata still exposes the authenticated conversation binding
  /// for hosts that need to route group payloads before decrypting them.
  PqcGroupPayloadMetadata? inspect(String payload) {
    try {
      final envelope = PqcV3Envelope.decode(payload);
      if (!envelope.isGroup ||
          envelope.conversationId == null ||
          envelope.conversationId! <= 0 ||
          envelope.conversationType == null) {
        return null;
      }
      return PqcGroupPayloadMetadata(
        conversationId: envelope.conversationId!,
        conversationType: envelope.conversationType!,
        epochId: '',
      );
    } catch (_) {
      return null;
    }
  }

  /// Verifies that a candidate group send covers exactly the active
  /// member-device keysets supplied by the host's membership service. This is
  /// intentionally host-fed: the SDK owns no mutable group directory.
  void _assertCoverage({
    required Iterable<PqcDevicePublicKey> actual,
    required Iterable<PqcDevicePublicKey> expected,
    required PqcDevicePublicKey sender,
  }) {
    Set<String> ids(Iterable<PqcDevicePublicKey> values) => {
      for (final value in values) '${value.deviceId}|${value.keysetId}',
    };
    final actualIds = ids([...actual, sender]);
    final expectedIds = ids([...expected, sender]);
    if (actualIds.length != expectedIds.length ||
        !actualIds.containsAll(expectedIds)) {
      throw StateError(
        'V3 group recipient coverage does not match the active member devices.',
      );
    }
  }
}
