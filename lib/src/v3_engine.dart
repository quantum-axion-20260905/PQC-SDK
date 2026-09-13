import 'models.dart';
import 'primitives.dart';
import 'v2_engine.dart';
import 'v3_attachment_codec.dart';
import 'v3_group_codec.dart';
import 'v3_private_codec.dart';

/// Standalone V3 engine.  It has no Flutter, storage, HTTP or server imports.
/// Platform applications only supply durable keysets, trust state and remote
/// capability negotiation through the SDK's host interfaces.
class PqcV3Engine implements PqcEngine {
  PqcV3Engine({PqcPrimitiveSuite? primitives})
    : primitives = primitives ?? DartPqcPrimitiveSuite() {
    private = PqcV3PrivateCodec(this.primitives);
    group = PqcV3GroupCodec(this.primitives);
    attachment = PqcV3AttachmentCodec(this.primitives);
  }

  final PqcPrimitiveSuite primitives;
  late final PqcV3PrivateCodec private;
  late final PqcV3GroupCodec group;
  late final PqcV3AttachmentCodec attachment;

  @override
  String get engineId => 'pqc-v3';

  @override
  String get wireProtocolId => 'v3';

  @override
  int get protocolVersion => PqcV3Wire.protocolVersion;

  @override
  String get privatePrefix => PqcV3Wire.privatePrefix;

  @override
  String get groupPrefix => PqcV3Wire.groupPrefix;

  @override
  String get privateAlgorithm => PqcV3Wire.privateAlgorithm;

  @override
  String get groupAlgorithm => PqcV3Wire.groupAlgorithm;

  @override
  Set<String> get attachmentCipherVersions => const {
    PqcV3Wire.attachmentCipherVersion,
  };

  @override
  bool recognizesPrivate(String payload) =>
      payload.startsWith('$privatePrefix:');

  @override
  bool recognizesGroup(String payload) => payload.startsWith('$groupPrefix:');

  @override
  PqcDeviceKeyset generateDeviceKeyset(String deviceId) =>
      primitives.generateDeviceKeyset(deviceId);

  @override
  Future<PqcDecodeResult> decryptPrivate({
    required PqcConversation conversation,
    required String payload,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) => private.decrypt(
    conversation: conversation,
    payload: payload,
    localKeysets: localKeysets,
    trustedSigningKeysByDevice: trustedSigningKeysByDevice,
  );

  @override
  PqcGroupPayloadMetadata? inspectGroup(String payload) =>
      group.inspect(payload);

  @override
  Future<PqcDecodeResult> decryptGroup({
    required PqcConversation conversation,
    required String payload,
    required Map<String, PqcGroupEpoch> epochsById,
    Iterable<PqcDeviceKeyset> localKeysets = const [],
    Map<String, Set<String>> trustedSigningKeysByDevice = const {},
  }) => group.decrypt(
    conversation: conversation,
    payload: payload,
    localKeysets: localKeysets,
    trustedSigningKeysByDevice: trustedSigningKeysByDevice,
  );
}
