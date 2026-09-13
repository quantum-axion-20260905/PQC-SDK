import 'models.dart';
import 'v2_engine.dart';

enum PqcConversationKind { private, group }

class PqcWireProtocol {
  const PqcWireProtocol({required this.id, required this.version});

  final String id;
  final int version;
}

abstract final class PqcWireProtocols {
  static const v2 = PqcWireProtocol(id: 'v2', version: 2);
  static const v3 = PqcWireProtocol(id: 'v3', version: 3);
}

class PqcEngineReleaseProfile {
  const PqcEngineReleaseProfile({
    required this.releaseId,
    required this.wireProtocol,
    required this.activeWriterEngineId,
    required this.requiredDecoderIds,
  });

  final String releaseId;
  final PqcWireProtocol wireProtocol;
  final String activeWriterEngineId;
  final Set<String> requiredDecoderIds;
}

abstract final class PqcReleaseProfiles {
  static const v2 = PqcEngineReleaseProfile(
    releaseId: '2.0.0',
    wireProtocol: PqcWireProtocols.v2,
    activeWriterEngineId: 'pqc-v2',
    requiredDecoderIds: {'pqc-v2'},
  );

  /// V2.5 keeps the V2 protocol family while using authenticated V2 writes.
  static const v25 = PqcEngineReleaseProfile(
    releaseId: '2.5.0',
    wireProtocol: PqcWireProtocols.v2,
    activeWriterEngineId: 'pqc-v2.5-writer',
    requiredDecoderIds: {'pqc-v2'},
  );

  /// V3 writes only its own wire format but permanently retains the V2 history
  /// decoder. The release profile is intentionally separate from V2.5: an
  /// application chooses one profile, it does not silently downgrade writes.
  static const v3 = PqcEngineReleaseProfile(
    releaseId: '3.0.0',
    wireProtocol: PqcWireProtocols.v3,
    activeWriterEngineId: 'pqc-v3',
    requiredDecoderIds: {'pqc-v2', 'pqc-v3'},
  );
}

class PqcCompatibilityException implements Exception {
  const PqcCompatibilityException(this.message);

  final String message;

  @override
  String toString() => 'PqcCompatibilityException: $message';
}

/// Registry and production write gate for independently versioned engines.
///
/// A recognized payload is offered to exactly one decoder. A cryptographic
/// failure is never retried as another protocol, preventing downgrade bugs.
class PqcEngineManager {
  PqcEngineManager({
    required Iterable<PqcEngine> decoders,
    PqcEngine? activeWriter,
    String? activeWriterId,
    this.writerEnabled = false,
    this.releaseProfile = PqcReleaseProfiles.v2,
  }) {
    // A host may pass a lazy or single-use iterable. Materialize it once so
    // validation and registration observe the same decoder set.
    final decoderList = List<PqcEngine>.of(decoders, growable: false);
    _decoders = {for (final engine in decoderList) engine.engineId: engine};
    if (_decoders.isEmpty) {
      throw ArgumentError('At least one decoder must be registered.');
    }
    if (_decoders.length != decoderList.length) {
      throw ArgumentError('Engine ids must be unique.');
    }
    if (activeWriter != null && activeWriterId != null) {
      throw ArgumentError(
        'Use activeWriter or the legacy activeWriterId, not both.',
      );
    }
    if (activeWriterId != null && !_decoders.containsKey(activeWriterId)) {
      throw ArgumentError('Active writer must be a registered engine.');
    }
    final registeredWriter = activeWriter == null
        ? null
        : _decoders[activeWriter.engineId];
    if (activeWriter != null &&
        registeredWriter != null &&
        !identical(registeredWriter, activeWriter)) {
      throw ArgumentError(
        'An active writer with a registered engine id must be the same instance '
        'as that registered decoder.',
      );
    }
    final missing = releaseProfile.requiredDecoderIds.difference(
      _decoders.keys.toSet(),
    );
    if (missing.isNotEmpty) {
      throw ArgumentError('Required historical decoders are missing: $missing');
    }
    _activeWriter =
        activeWriter ??
        (activeWriterId == null ? null : _decoders[activeWriterId]);
    final writer = _activeWriter;
    if (writer != null &&
        (writer.wireProtocolId != releaseProfile.wireProtocol.id ||
            writer.protocolVersion != releaseProfile.wireProtocol.version)) {
      throw ArgumentError(
        'Release ${releaseProfile.releaseId} requires wire protocol '
        '${releaseProfile.wireProtocol.id}.',
      );
    }
    if (writer != null &&
        writer.engineId != releaseProfile.activeWriterEngineId) {
      throw ArgumentError(
        'Release ${releaseProfile.releaseId} requires writer '
        '${releaseProfile.activeWriterEngineId}.',
      );
    }
  }

  late final Map<String, PqcEngine> _decoders;
  late final PqcEngine? _activeWriter;
  final bool writerEnabled;
  final PqcEngineReleaseProfile releaseProfile;

  String get releaseId => releaseProfile.releaseId;

  String get wireProtocolId => releaseProfile.wireProtocol.id;

  List<PqcEngine> get decoders => List.unmodifiable(_decoders.values);

  PqcEngine? get activeWriter => _activeWriter;

  PqcEngine resolveDecoder({
    required PqcConversationKind kind,
    required String payload,
  }) {
    final matches = _decoders.values
        .where((engine) {
          return kind == PqcConversationKind.private
              ? engine.recognizesPrivate(payload)
              : engine.recognizesGroup(payload);
        })
        .toList(growable: false);
    if (matches.isEmpty) {
      throw const PqcCompatibilityException('Unsupported payload format.');
    }
    if (matches.length != 1) {
      throw const PqcCompatibilityException(
        'Ambiguous payload format registration.',
      );
    }
    return matches.single;
  }

  PqcEngine requireWriter({
    required PqcConversationKind kind,
    required PqcRemoteCapabilities remote,
  }) {
    final writer = activeWriter;
    if (!writerEnabled || writer == null) {
      throw const PqcCompatibilityException(
        'Encrypted writer is disabled by the production gate.',
      );
    }
    final readable = kind == PqcConversationKind.private
        ? remote.privateReadPrefixes.contains(writer.privatePrefix)
        : remote.groupReadPrefixes.contains(writer.groupPrefix);
    final writable = kind == PqcConversationKind.private
        ? remote.privateWritePrefixes.contains(writer.privatePrefix)
        : remote.groupWritePrefixes.contains(writer.groupPrefix);
    if (!readable || !writable) {
      throw PqcCompatibilityException(
        'Remote endpoint cannot safely read and write ${writer.engineId}.',
      );
    }
    final algorithmSupported = kind == PqcConversationKind.private
        ? remote.privateAlgorithms.contains(writer.privateAlgorithm)
        : remote.groupAlgorithms.contains(writer.groupAlgorithm);
    if (!algorithmSupported) {
      throw PqcCompatibilityException(
        'Remote endpoint cannot read and write the authenticated '
        '${kind == PqcConversationKind.private ? 'private' : 'group'} '
        'algorithm for ${writer.engineId}.',
      );
    }
    if (writer.protocolVersion < remote.minimumDecoderVersion) {
      throw PqcCompatibilityException(
        'Remote endpoint requires decoder version '
        '${remote.minimumDecoderVersion} or newer.',
      );
    }
    if (!writer.attachmentCipherVersions.every(
      remote.attachmentCipherVersions.contains,
    )) {
      throw const PqcCompatibilityException(
        'Attachment cipher capability mismatch.',
      );
    }
    return writer;
  }
}
