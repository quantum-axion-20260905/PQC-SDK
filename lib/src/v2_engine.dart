import 'models.dart';
import 'primitives.dart';
import 'v2_attachment_codec.dart';
import 'v2_authenticated_group_codec.dart';
import 'v2_group_codec.dart';
import 'v2_private_codec.dart';

abstract interface class PqcEngine {
  String get engineId;
  String get wireProtocolId;
  int get protocolVersion;
  String get privatePrefix;
  String get groupPrefix;
  String get privateAlgorithm;
  String get groupAlgorithm;
  Set<String> get attachmentCipherVersions;

  bool recognizesPrivate(String payload);
  bool recognizesGroup(String payload);

  PqcDeviceKeyset generateDeviceKeyset(String deviceId);

  Future<PqcDecodeResult> decryptPrivate({
    required PqcConversation conversation,
    required String payload,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  });

  PqcGroupPayloadMetadata? inspectGroup(String payload);

  Future<PqcDecodeResult> decryptGroup({
    required PqcConversation conversation,
    required String payload,
    required Map<String, PqcGroupEpoch> epochsById,
    Iterable<PqcDeviceKeyset> localKeysets = const [],
    Map<String, Set<String>> trustedSigningKeysByDevice = const {},
  });
}

class PqcV2Engine implements PqcEngine {
  PqcV2Engine({PqcPrimitiveSuite? primitives})
    : primitives = primitives ?? DartPqcPrimitiveSuite() {
    private = PqcV2PrivateCodec(this.primitives);
    group = PqcV2GroupCodec(this.primitives);
    authenticatedGroup = PqcV2AuthenticatedGroupCodec(this.primitives);
    attachment = PqcV2AttachmentCodec(this.primitives);
  }

  final PqcPrimitiveSuite primitives;
  late final PqcV2PrivateCodec private;
  late final PqcV2GroupCodec group;
  late final PqcV2AuthenticatedGroupCodec authenticatedGroup;
  late final PqcV2AttachmentCodec attachment;

  @override
  String get engineId => 'pqc-v2';

  @override
  String get wireProtocolId => 'v2';

  @override
  int get protocolVersion => PqcV2Wire.protocolVersion;

  @override
  String get privatePrefix => PqcV2Wire.privatePrefix;

  @override
  String get groupPrefix => PqcV2Wire.groupPrefix;

  @override
  String get privateAlgorithm => PqcV2Wire.privateAlgorithm;

  @override
  String get groupAlgorithm => PqcV2Wire.groupAlgorithm;

  @override
  Set<String> get attachmentCipherVersions => const {
    PqcV2Wire.attachmentCipherVersion,
  };

  @override
  bool recognizesPrivate(String payload) =>
      payload.startsWith('$privatePrefix:');

  @override
  bool recognizesGroup(String payload) =>
      payload.startsWith('$groupPrefix:') ||
      payload.startsWith('${PqcV2Wire.authenticatedGroupPrefix}:');

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
      payload.startsWith('${PqcV2Wire.authenticatedGroupPrefix}:')
      ? authenticatedGroup.inspect(payload)
      : group.inspect(payload);

  @override
  Future<PqcDecodeResult> decryptGroup({
    required PqcConversation conversation,
    required String payload,
    required Map<String, PqcGroupEpoch> epochsById,
    Iterable<PqcDeviceKeyset> localKeysets = const [],
    Map<String, Set<String>> trustedSigningKeysByDevice = const {},
  }) => payload.startsWith('${PqcV2Wire.authenticatedGroupPrefix}:')
      ? authenticatedGroup.decrypt(
          conversation: conversation,
          payload: payload,
          epochsById: epochsById,
          trustedSigningKeysByDevice: trustedSigningKeysByDevice,
        )
      : group.decrypt(
          conversation: conversation,
          payload: payload,
          epochsById: epochsById,
          trustedSigningKeysByDevice: trustedSigningKeysByDevice,
        );
}
