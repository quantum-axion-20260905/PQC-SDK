import 'v2_engine.dart';

/// V2.5 production writer profile.
///
/// It reuses the V2 authenticated codecs. It is registered only as the active
/// writer; historical reads remain owned by the [PqcV2Engine] decoder
/// registration.
class PqcV25Writer extends PqcV2Engine {
  PqcV25Writer({super.primitives});

  @override
  String get engineId => 'pqc-v2.5-writer';
}
