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

      // Bob sends reply to Alice (Full bidirectional test)
      final bobReplyPayload = await bobSession.encrypt(
        plaintext: 'Salom Alice! Qabul qildim va javob yozyapman #0',
        remoteKemPublicKeyBase64: aliceKeys.kemPublicKeyBase64,
      );

      final decryptedReply = await aliceSession.decrypt(
        payload: bobReplyPayload,
        trustedRemoteSigningKeys: {bobKeys.signingPublicKeyBase64},
      );
      expect(decryptedReply, 'Salom Alice! Qabul qildim va javob yozyapman #0');

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

    test('handles out-of-order message arrival seamlessly', () async {
      const conversationId = 888;
      final handshake = await PqcRatchetSession.createInitiator(
        conversationId: conversationId,
        localDevice: aliceKeys,
        remoteDevice: bobKeys.publicKey,
        primitives: primitives,
      );
      final alice = handshake.session;
      final bob = await PqcRatchetSession.createResponder(
        conversationId: conversationId,
        localDevice: bobKeys,
        remoteDeviceId: aliceKeys.deviceId,
        initialKemCiphertextBase64: handshake.initialKemCiphertextBase64,
        primitives: primitives,
      );

      // Alice sends messages 0, 1, 2
      final msg0 = await alice.encrypt(
        plaintext: 'Message 0',
        remoteKemPublicKeyBase64: bobKeys.kemPublicKeyBase64,
      );
      final msg1 = await alice.encrypt(
        plaintext: 'Message 1',
        remoteKemPublicKeyBase64: bobKeys.kemPublicKeyBase64,
      );
      final msg2 = await alice.encrypt(
        plaintext: 'Message 2',
        remoteKemPublicKeyBase64: bobKeys.kemPublicKeyBase64,
      );

      // Bob receives Message 0 first
      expect(
        await bob.decrypt(
          payload: msg0,
          trustedRemoteSigningKeys: {aliceKeys.signingPublicKeyBase64},
        ),
        'Message 0',
      );

      // Network delivers Message 2 before Message 1 (out-of-order)
      expect(
        await bob.decrypt(
          payload: msg2,
          trustedRemoteSigningKeys: {aliceKeys.signingPublicKeyBase64},
        ),
        'Message 2',
      );

      // Later, delayed Message 1 arrives and decrypts cleanly via skipped message cache
      expect(
        await bob.decrypt(
          payload: msg1,
          trustedRemoteSigningKeys: {aliceKeys.signingPublicKeyBase64},
        ),
        'Message 1',
      );

      // Duplicate / replay of delayed message now fails
      expect(
        () => bob.decrypt(
          payload: msg1,
          trustedRemoteSigningKeys: {aliceKeys.signingPublicKeyBase64},
        ),
        throwsA(isA<FormatException>()),
      );

      alice.dispose();
      bob.dispose();
    });
  });

  group('Hybrid Cryptography (Classical + Post-Quantum)', () {
    test('deriveHybridSharedSecret blends classical and PQC entropy', () async {
      final classicalX25519Secret = List<int>.generate(32, (i) => i + 1);
      final pqcKyber768Secret = List<int>.generate(32, (i) => 255 - i);

      final hybrid1 = await deriveHybridSharedSecret(
        classicalSecret: classicalX25519Secret,
        postQuantumSecret: pqcKyber768Secret,
      );

      final hybrid2 = await deriveHybridSharedSecret(
        classicalSecret: classicalX25519Secret,
        postQuantumSecret: pqcKyber768Secret,
      );

      // Deterministic derivation for identical inputs
      expect(hybrid1.length, 32);
      expect(hybrid1, equals(hybrid2));

      // Altering classical secret changes output
      final alteredClassical = List<int>.from(classicalX25519Secret)..[0] ^= 0x01;
      final hybridDifferentClassical = await deriveHybridSharedSecret(
        classicalSecret: alteredClassical,
        postQuantumSecret: pqcKyber768Secret,
      );
      expect(hybrid1, isNot(equals(hybridDifferentClassical)));

      // Altering PQC secret changes output
      final alteredPqc = List<int>.from(pqcKyber768Secret)..[0] ^= 0x01;
      final hybridDifferentPqc = await deriveHybridSharedSecret(
        classicalSecret: classicalX25519Secret,
        postQuantumSecret: alteredPqc,
      );
      expect(hybrid1, isNot(equals(hybridDifferentPqc)));
    });
  });

  group('Memory Zeroization & Keysets', () {
    test('PqcGroupEpoch.zeroize clears backing buffer in place', () {
      final secret = [10, 20, 30, 40, 50];
      final epoch = PqcGroupEpoch(epochId: 'ep-1', secretKeyBytes: secret);
      expect(epoch.secretKeyBytes.any((b) => b != 0), isTrue);

      epoch.zeroize();
      expect(epoch.secretKeyBytes.every((b) => b == 0), isTrue);
    });

    test('PqcDeviceKeyset copy helpers produce zeroizable byte buffers', () {
      final suite = DartPqcPrimitiveSuite();
      final keyset = suite.generateDeviceKeyset('dev-1');

      final kemSecret = keyset.copyKemSecretKey();
      expect(kemSecret.length, DartPqcPrimitiveSuite.kemSecretKeyLength);
      expect(kemSecret.any((b) => b != 0), isTrue);

      secureZero(kemSecret);
      expect(kemSecret.every((b) => b == 0), isTrue);
    });
  });

  group('PqcAtomicReplayStore Sliding Window Eviction', () {
    test('evicts oldest entries when maxEntries is specified', () async {
      final memoryStore = PqcMemoryAtomicStore();
      final store = PqcAtomicReplayStore(memoryStore, maxEntries: 2);

      // Claim 2 messages
      final r1 = await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-1',
        payloadDigest: 'a' * 64,
      );
      expect(r1, isNull);

      final r2 = await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-2',
        payloadDigest: 'b' * 64,
      );
      expect(r2, isNull);

      // msg-1 is still remembered as duplicate
      final dup1 = await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-1',
        payloadDigest: 'a' * 64,
      );
      expect(dup1, 'a' * 64);

      // Claim 3rd message -> triggers eviction of msg-1 from the window of 2
      final r3 = await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-3',
        payloadDigest: 'c' * 64,
      );
      expect(r3, isNull);

      // msg-2 and msg-3 remain
      final dup2 = await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-2',
        payloadDigest: 'b' * 64,
      );
      expect(dup2, 'b' * 64);

      final dup3 = await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-3',
        payloadDigest: 'c' * 64,
      );
      expect(dup3, 'c' * 64);
    });
  });
}
