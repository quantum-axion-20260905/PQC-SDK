import 'models.dart';
import 'v2_engine.dart';

/// Explicit read-only facade for frozen V2 history in a V2.5 or V3 release.
///
/// It deliberately exposes no encrypt methods.  Register this as `pqc-v2` in
/// a newer [PqcEngineManager] so retained history cannot accidentally become a
/// fallback writer.
class PqcV2CompatibilityDecoder implements PqcEngine {
  PqcV2CompatibilityDecoder({PqcV2Engine? engine})
    : _engine = engine ?? PqcV2Engine();

  final PqcV2Engine _engine;

  @override
  String get engineId => 'pqc-v2';

  @override
  String get wireProtocolId => _engine.wireProtocolId;

  @override
  int get protocolVersion => _engine.protocolVersion;

  @override
  String get privatePrefix => _engine.privatePrefix;

  @override
  String get groupPrefix => _engine.groupPrefix;

  @override
  String get privateAlgorithm => _engine.privateAlgorithm;

  @override
  String get groupAlgorithm => _engine.groupAlgorithm;

  @override
  Set<String> get attachmentCipherVersions => _engine.attachmentCipherVersions;

  @override
  bool recognizesPrivate(String payload) => _engine.recognizesPrivate(payload);

  @override
  bool recognizesGroup(String payload) => _engine.recognizesGroup(payload);

  @override
  PqcDeviceKeyset generateDeviceKeyset(String deviceId) =>
      _engine.generateDeviceKeyset(deviceId);

  @override
  Future<PqcDecodeResult> decryptPrivate({
    required PqcConversation conversation,
    required String payload,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) => _engine.decryptPrivate(
    conversation: conversation,
    payload: payload,
    localKeysets: localKeysets,
    trustedSigningKeysByDevice: trustedSigningKeysByDevice,
  );

  @override
  PqcGroupPayloadMetadata? inspectGroup(String payload) =>
      _engine.inspectGroup(payload);

  @override
  Future<PqcDecodeResult> decryptGroup({
    required PqcConversation conversation,
    required String payload,
    required Map<String, PqcGroupEpoch> epochsById,
    Iterable<PqcDeviceKeyset> localKeysets = const [],
    Map<String, Set<String>> trustedSigningKeysByDevice = const {},
  }) => _engine.decryptGroup(
    conversation: conversation,
    payload: payload,
    epochsById: epochsById,
    localKeysets: localKeysets,
    trustedSigningKeysByDevice: trustedSigningKeysByDevice,
  );
}
