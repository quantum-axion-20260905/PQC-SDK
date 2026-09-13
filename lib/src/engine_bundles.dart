import 'primitives.dart';
import 'v2_compatibility_decoder.dart';
import 'v2_engine.dart';
import 'v25_writer.dart';
import 'v3_engine.dart';
import 'version_manager.dart';

/// A complete, internally consistent engine installation for one release.
///
/// Hosts should use a bundle instead of independently assembling decoders and
/// writers. This avoids accidentally registering V2.5 as a decoder or
/// omitting the V2 history reader during an upgrade.
class PqcEngineBundle {
  const PqcEngineBundle({
    required this.manager,
    required this.writer,
    required this.decoders,
  });

  final PqcEngineManager manager;
  final PqcEngine writer;
  final List<PqcEngine> decoders;
}

/// Canonical release assembly.  These factories do not open the writer gate;
/// the host must explicitly opt in only after its recovery and capability
/// checks are ready.
abstract final class PqcEngineBundles {
  /// V2 release assembly with authenticated group writes and legacy history
  /// decoding.
  static PqcEngineBundle v2({
    PqcPrimitiveSuite? primitives,
    bool writerEnabled = false,
  }) {
    final writer = PqcV2Engine(primitives: primitives);
    return PqcEngineBundle(
      manager: PqcEngineManager(
        decoders: [writer],
        activeWriter: writer,
        writerEnabled: writerEnabled,
        releaseProfile: PqcReleaseProfiles.v2,
      ),
      writer: writer,
      decoders: List.unmodifiable([writer]),
    );
  }

  static PqcEngineBundle v25({
    PqcPrimitiveSuite? primitives,
    bool writerEnabled = false,
  }) {
    final suite = primitives ?? DartPqcPrimitiveSuite();
    final decoder = PqcV2CompatibilityDecoder(
      engine: PqcV2Engine(primitives: suite),
    );
    final writer = PqcV25Writer(primitives: suite);
    return PqcEngineBundle(
      manager: PqcEngineManager(
        decoders: [decoder],
        activeWriter: writer,
        writerEnabled: writerEnabled,
        releaseProfile: PqcReleaseProfiles.v25,
      ),
      writer: writer,
      decoders: List.unmodifiable([decoder]),
    );
  }

  static PqcEngineBundle v3({
    PqcPrimitiveSuite? primitives,
    bool writerEnabled = false,
  }) {
    final suite = primitives ?? DartPqcPrimitiveSuite();
    final v2Decoder = PqcV2CompatibilityDecoder(
      engine: PqcV2Engine(primitives: suite),
    );
    final writer = PqcV3Engine(primitives: suite);
    final decoders = <PqcEngine>[v2Decoder, writer];
    return PqcEngineBundle(
      manager: PqcEngineManager(
        decoders: decoders,
        activeWriter: writer,
        writerEnabled: writerEnabled,
        releaseProfile: PqcReleaseProfiles.v3,
      ),
      writer: writer,
      decoders: List.unmodifiable(decoders),
    );
  }
}
