import 'dart:convert';
import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';

void main() async {
  final v2 = PqcV2Engine();
  final v3 = PqcV3Engine();
  if (v2.protocolVersion != PqcV2Wire.protocolVersion ||
      v3.protocolVersion != PqcV3Wire.protocolVersion) {
    throw StateError('Unexpected protocol version.');
  }

  // Verify CSPRNG does not generate all zeros (Web 1<<32 regression test)
  final primitives = DartPqcPrimitiveSuite();
  final random = primitives.randomBytes(32);
  if (random.every((b) => b == 0)) {
    throw StateError('CSPRNG produced all zeros on Web platform.');
  }

  // Verify ML-KEM and ML-DSA key generation & signatures
  final keys = primitives.generateDeviceKeyset('web-smoke-device');
  final msg = utf8.encode('web-smoke-check');
  final sig = primitives.sign(
    message: msg,
    secretKeyBase64: keys.signingSecretKeyBase64,
  );
  if (!primitives.verify(
    message: msg,
    signatureBase64: sig,
    publicKeyBase64: keys.signingPublicKeyBase64,
  )) {
    throw StateError('ML-DSA verification failed in web smoke.');
  }

  // Verify ML-KEM encapsulate/decapsulate
  final kem = primitives.encapsulate(keys.kemPublicKeyBase64);
  final clearSecret = primitives.decapsulate(
    ciphertextBase64: kem.ciphertextBase64,
    secretKeyBase64: keys.kemSecretKeyBase64,
  );
  if (!constantTimeBytesEquals(kem.sharedSecret, clearSecret)) {
    throw StateError('ML-KEM decapsulate mismatch in web smoke.');
  }

  print('Web smoke verification passed!');
}
