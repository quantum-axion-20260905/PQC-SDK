import 'dart:convert';
import 'dart:typed_data';

import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('Cryptographic Utilities and Timing-Attack Protection', () {
    test('constantTimeBytesEquals identifies matches and mismatches', () {
      final a = [1, 2, 3, 4, 5];
      final b = [1, 2, 3, 4, 5];
      final c = [1, 2, 3, 4, 6];
      final d = [1, 2, 3];

      expect(constantTimeBytesEquals(a, b), isTrue);
      expect(constantTimeBytesEquals(a, c), isFalse);
      expect(constantTimeBytesEquals(a, d), isFalse);
      expect(constantTimeBytesEquals([], []), isTrue);
    });

    test('constantTimeStringEquals correctly verifies tokens in constant time', () {
      expect(constantTimeStringEquals('token_abc_123', 'token_abc_123'), isTrue);
      expect(constantTimeStringEquals('token_abc_123', 'token_abc_124'), isFalse);
      expect(constantTimeStringEquals('token_abc', 'token_abc_123'), isFalse);
      expect(constantTimeStringEquals('', ''), isTrue);
    });

    test('secureZero overwrites sensitive buffer in place', () {
      final secret = Uint8List.fromList([0xAA, 0xBB, 0xCC, 0xDD]);
      expect(secret.any((byte) => byte != 0), isTrue);

      secureZero(secret);
      expect(secret.every((byte) => byte == 0), isTrue);
    });

    test('wipeBytes overwrites generic list in place', () {
      final list = [1, 2, 3, 4];
      wipeBytes(list);
      expect(list.every((byte) => byte == 0), isTrue);
    });
  });

  group('RFC 8785 Canonical JSON Serialization', () {
    test('lexicographically sorts object keys regardless of insertion order', () {
      final map1 = {'z': 1, 'a': 2, 'm': 3};
      final map2 = {'a': 2, 'm': 3, 'z': 1};

      expect(canonicalJsonEncode(map1), '{"a":2,"m":3,"z":1}');
      expect(canonicalJsonEncode(map1), equals(canonicalJsonEncode(map2)));
    });

    test('handles nested structures and primitive data types cleanly', () {
      final data = {
        'user': {
          'active': true,
          'id': 42,
          'roles': ['admin', 'user'],
        },
        'count': 100,
      };

      expect(
        canonicalJsonEncode(data),
        '{"count":100,"user":{"active":true,"id":42,"roles":["admin","user"]}}',
      );
    });
  });

  group('PQC Ratchet Session (Forward Secrecy & Post-Compromise Security)', () {
    late PqcPrimitiveSuite primitives;
    late PqcDeviceKeyset aliceKeys;
    late PqcDeviceKeyset bobKeys;

    setUp(() {
      primitives = DartPqcPrimitiveSuite();
      aliceKeys = primitives.generateDeviceKeyset('alice-device');
      bobKeys = primitives.generateDeviceKeyset('bob-device');
    });

    test('bidirectional ratcheted exchange with forward secrecy', () async {
      const conversationId = 777;

      // 1. Initial handshake: Alice initiates
      final handshake = await PqcRatchetSession.createInitiator(
        conversationId: conversationId,
        localDevice: aliceKeys,
        remoteDevice: bobKeys.publicKey,
        primitives: primitives,
      );
      final aliceSession = handshake.session;

      final bobSession = await PqcRatchetSession.createResponder(
        conversationId: conversationId,
        localDevice: bobKeys,
        remoteDeviceId: aliceKeys.deviceId,
        initialKemCiphertextBase64: handshake.initialKemCiphertextBase64,
        primitives: primitives,
      );

      // Alice sends message 0
      final msg0Payload = await aliceSession.encrypt(
        plaintext: 'Salom Bob! Kvant xavfsiz ratchet xabari #0',
        remoteKemPublicKeyBase64: bobKeys.kemPublicKeyBase64,
      );

      expect(msg0Payload, startsWith('${PqcRatchetEnvelope.prefix}:'));

      // Bob receives and decrypts message 0
      final decrypted0 = await bobSession.decrypt(
        payload: msg0Payload,
        trustedRemoteSigningKeys: {aliceKeys.signingPublicKeyBase64},
      );
      expect(decrypted0, 'Salom Bob! Kvant xavfsiz ratchet xabari #0');

      // Alice sends message 1 (Forward Secrecy step)
      final msg1Payload = await aliceSession.encrypt(
        plaintext: 'Alice dan ikkinchi xabar #1',
        remoteKemPublicKeyBase64: bobKeys.kemPublicKeyBase64,
      );

      final decrypted1 = await bobSession.decrypt(
        payload: msg1Payload,
        trustedRemoteSigningKeys: {aliceKeys.signingPublicKeyBase64},
      );
      expect(decrypted1, 'Alice dan ikkinchi xabar #1');

      // Replay of msg0 should fail because sequence has advanced
      expect(
        () => bobSession.decrypt(
          payload: msg0Payload,
          trustedRemoteSigningKeys: {aliceKeys.signingPublicKeyBase64},
        ),
        throwsA(isA<FormatException>()),
      );

      // Tampered payload fails ML-DSA authentication
      final tamperedBytes = utf8.encode(msg1Payload).toList();
      tamperedBytes[tamperedBytes.length - 5] ^= 0x01;
      expect(
        () => bobSession.decrypt(
          payload: utf8.decode(tamperedBytes),
          trustedRemoteSigningKeys: {aliceKeys.signingPublicKeyBase64},
        ),
        throwsA(anything),
      );

      // Disposal wipes keys and prevents further operations
      aliceSession.dispose();
      bobSession.dispose();

      expect(aliceSession.isDisposed, isTrue);
      expect(bobSession.isDisposed, isTrue);

      expect(
        () => aliceSession.encrypt(
          plaintext: 'dead write',
          remoteKemPublicKeyBase64: bobKeys.kemPublicKeyBase64,
        ),
        throwsStateError,
      );
    });
  });
}
