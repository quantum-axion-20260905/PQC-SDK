import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:pqcrypto/pqcrypto.dart';

import 'models.dart';

class PqcAeadBox {
  PqcAeadBox({
    required List<int> nonce,
    required List<int> ciphertext,
    required List<int> mac,
  }) : nonce = Uint8List.fromList(nonce),
       ciphertext = Uint8List.fromList(ciphertext),
       mac = Uint8List.fromList(mac);

  final Uint8List nonce;
  final Uint8List ciphertext;
  final Uint8List mac;
}

class PqcKemEnvelope {
  PqcKemEnvelope({
    required this.ciphertextBase64,
    required List<int> sharedSecret,
  }) : sharedSecret = Uint8List.fromList(sharedSecret);

  final String ciphertextBase64;
  final Uint8List sharedSecret;
}

abstract interface class PqcPrimitiveSuite {
  PqcDeviceKeyset generateDeviceKeyset(String deviceId);

  PqcKemEnvelope encapsulate(String publicKeyBase64);

  Uint8List decapsulate({
    required String ciphertextBase64,
    required String secretKeyBase64,
  });

  String sign({required List<int> message, required String secretKeyBase64});

  bool verify({
    required List<int> message,
    required String signatureBase64,
    required String publicKeyBase64,
  });

  Future<PqcAeadBox> encryptAead({
    required List<int> plaintext,
    required List<int> key,
    required List<int> nonce,
    List<int> associatedData = const [],
  });

  Future<Uint8List> decryptAead({
    required PqcAeadBox box,
    required List<int> key,
    List<int> associatedData = const [],
  });

  Future<Uint8List> deriveKey({
    required List<int> secret,
    required List<int> nonce,
    required List<int> info,
    int length = 32,
  });

  Uint8List randomBytes(int length);

  Uint8List sha256(List<int> value);
}

class DartPqcPrimitiveSuite implements PqcPrimitiveSuite {
  DartPqcPrimitiveSuite()
    : _random = Random.secure(),
      _kem = PqcKem.kyber768,
      _signingParams = DilithiumParams.mlDsa65,
      _cipher = AesGcm.with256bits();

  static const kemPublicKeyLength = 1184;
  static const kemSecretKeyLength = 2400;
  static const kemCiphertextLength = 1088;
  static const signingPublicKeyLength = 1952;
  static const signingSecretKeyLength = 4032;
  static const signingContext = 'pqc-chat-device-sign-v1';

  final Random _random;
  final KyberKem _kem;
  final DilithiumParams _signingParams;
  final AesGcm _cipher;

  @override
  PqcDeviceKeyset generateDeviceKeyset(String deviceId) {
    if (deviceId.trim().isEmpty) {
      throw ArgumentError.value(deviceId, 'deviceId', 'Must not be empty.');
    }
    final (kemPublic, kemSecret) = _kem.generateKeyPair();
    final (signingPublic, signingSecret) = MlDsa.generateKeyPair(
      _signingParams,
    );
    return PqcDeviceKeyset(
      deviceId: deviceId,
      kemPublicKeyBase64: base64Encode(kemPublic),
      kemSecretKeyBase64: base64Encode(kemSecret),
      signingPublicKeyBase64: base64Encode(signingPublic),
      signingSecretKeyBase64: base64Encode(signingSecret),
    );
  }

  @override
  PqcKemEnvelope encapsulate(String publicKeyBase64) {
    final publicKey = _decodeLength(
      publicKeyBase64,
      kemPublicKeyLength,
      'ML-KEM public key',
    );
    final (ciphertext, sharedSecret) = _kem.encapsulate(publicKey);
    return PqcKemEnvelope(
      ciphertextBase64: base64Encode(ciphertext),
      sharedSecret: sharedSecret,
    );
  }

  @override
  Uint8List decapsulate({
    required String ciphertextBase64,
    required String secretKeyBase64,
  }) {
    final ciphertext = _decodeLength(
      ciphertextBase64,
      kemCiphertextLength,
      'ML-KEM ciphertext',
    );
    final secretKey = _decodeLength(
      secretKeyBase64,
      kemSecretKeyLength,
      'ML-KEM secret key',
    );
    return _kem.decapsulate(secretKey, ciphertext);
  }

  @override
  String sign({required List<int> message, required String secretKeyBase64}) {
    final secretKey = _decodeLength(
      secretKeyBase64,
      signingSecretKeyLength,
      'ML-DSA secret key',
    );
    return base64Encode(
      MlDsa.sign(
        secretKey,
        Uint8List.fromList(message),
        _signingParams,
        ctx: Uint8List.fromList(signingContext.codeUnits),
      ),
    );
  }

  @override
  bool verify({
    required List<int> message,
    required String signatureBase64,
    required String publicKeyBase64,
  }) {
    try {
      final publicKey = _decodeLength(
        publicKeyBase64,
        signingPublicKeyLength,
        'ML-DSA public key',
      );
      return MlDsa.verify(
        publicKey,
        Uint8List.fromList(message),
        base64Decode(signatureBase64),
        _signingParams,
        ctx: Uint8List.fromList(signingContext.codeUnits),
      );
    } catch (_) {
      return false;
    }
  }

  @override
  Future<PqcAeadBox> encryptAead({
    required List<int> plaintext,
    required List<int> key,
    required List<int> nonce,
    List<int> associatedData = const [],
  }) async {
    _requireLength(key, 32, 'AES-256 key');
    _requireLength(nonce, 12, 'AES-GCM nonce');
    final box = await _cipher.encrypt(
      plaintext,
      secretKey: SecretKey(key),
      nonce: nonce,
      aad: associatedData,
    );
    return PqcAeadBox(
      nonce: box.nonce,
      ciphertext: box.cipherText,
      mac: box.mac.bytes,
    );
  }

  @override
  Future<Uint8List> decryptAead({
    required PqcAeadBox box,
    required List<int> key,
    List<int> associatedData = const [],
  }) async {
    _requireLength(key, 32, 'AES-256 key');
    final clear = await _cipher.decrypt(
      SecretBox(box.ciphertext, nonce: box.nonce, mac: Mac(box.mac)),
      secretKey: SecretKey(key),
      aad: associatedData,
    );
    return Uint8List.fromList(clear);
  }

  @override
  Future<Uint8List> deriveKey({
    required List<int> secret,
    required List<int> nonce,
    required List<int> info,
    int length = 32,
  }) async {
    final key = await Hkdf(
      hmac: Hmac.sha256(),
      outputLength: length,
    ).deriveKey(secretKey: SecretKey(secret), nonce: nonce, info: info);
    return Uint8List.fromList(await key.extractBytes());
  }

  @override
  Uint8List randomBytes(int length) => Uint8List.fromList(
    List<int>.generate(length, (_) => _random.nextInt(256)),
  );

  @override
  Uint8List sha256(List<int> value) =>
      Uint8List.fromList(crypto.sha256.convert(value).bytes);

  Uint8List _decodeLength(String value, int length, String label) {
    final decoded = base64Decode(value);
    _requireLength(decoded, length, label);
    return Uint8List.fromList(decoded);
  }

  void _requireLength(List<int> value, int length, String label) {
    if (value.length != length) {
      throw ArgumentError('$label must be exactly $length bytes.');
    }
  }
}
