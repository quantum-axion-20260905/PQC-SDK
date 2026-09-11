import 'dart:convert';

import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';
import 'package:test/test.dart';

void main() {
  late PqcV3Engine engine;
  late PqcDeviceKeyset alice;
  late PqcDeviceKeyset bob;
  late PqcDeviceKeyset bobReplacement;
  late PqcDeviceKeyset carol;

  setUpAll(() {
    final primitives = DartPqcPrimitiveSuite();
    engine = PqcV3Engine(primitives: primitives);
    alice = primitives.generateDeviceKeyset('alice-phone');
    bob = primitives.generateDeviceKeyset('bob-tablet');
    bobReplacement = primitives.generateDeviceKeyset('bob-tablet-new');
    carol = primitives.generateDeviceKeyset('carol-web');
  });

  test('V3 envelope golden vector preserves canonical wire serialization', () {
    const envelope = PqcV3Envelope(
      isGroup: false,
      messageId: 'golden-1',
      senderDeviceId: 'sender',
      keysetId: 'keyset',
      ciphertext: 'AQID',
      conversationId: 9,
      conversationType: 'private',
      senderKeysetId: 'keyset',
      signingPublicKey: 'sign',
      wraps: [
        PqcV3RecipientWrap(
          deviceId: 'recipient',
          keysetId: 'recipient-keyset',
          kemCiphertext: 'kem',
          wrappedKey: 'wrap',
        ),
      ],
      signature: 'sig',
    );
    expect(
      envelope.encode(),
      'pqc:v3:eyJwcm90b2NvbF92ZXJzaW9uIjozLCJtZXNzYWdlX2lkIjoiZ29sZGVuLTEiLCJzZW5kZXJfZGV2aWNlX2lkIjoic2VuZGVyIiwia2V5c2V0X2lkIjoia2V5c2V0IiwiY2lwaGVydGV4dCI6IkFRSUQiLCJtZXRhZGF0YSI6e30sImNvbnZlcnNhdGlvbl9pZCI6OSwiY29udmVyc2F0aW9uX3R5cGUiOiJwcml2YXRlIiwic2VuZGVyX2tleXNldF9pZCI6ImtleXNldCIsInNpZ25pbmdfcHVibGljX2tleSI6InNpZ24iLCJ3cmFwcyI6W3siZGV2aWNlX2lkIjoicmVjaXBpZW50Iiwia2V5c2V0X2lkIjoicmVjaXBpZW50LWtleXNldCIsImtlbV9jaXBoZXJ0ZXh0Ijoia2VtIiwid3JhcHBlZF9rZXkiOiJ3cmFwIn1dLCJzaWduYXR1cmUiOiJzaWcifQ==',
    );
    expect(PqcV3Envelope.decode(envelope.encode()).toJson(), envelope.toJson());
  });

  test(
    'V3 envelope rejects malformed wrap entries instead of dropping them',
    () {
      final document = const PqcV3Envelope(
        isGroup: false,
        messageId: 'strict-wraps',
        senderDeviceId: 'sender',
        keysetId: 'keyset',
        ciphertext: 'ciphertext',
        wraps: [
          PqcV3RecipientWrap(
            deviceId: 'recipient',
            keysetId: 'recipient-keyset',
            kemCiphertext: 'kem',
            wrappedKey: 'wrap',
          ),
        ],
      ).toJson();
      document['wraps'] = [...(document['wraps'] as List), 'not-a-wrap'];

      expect(
        () => PqcV3Envelope.decode(_v3Payload(document, isGroup: false)),
        throwsA(isA<FormatException>()),
      );
    },
  );

  group('PQCv3 private recipient-wrap codec', () {
    const conversation = PqcConversation(id: 301, type: 'private');

    test('round-trips for every recipient and the sender history', () async {
      final payload = await engine.private.encrypt(
        conversation: conversation,
        messageId: 'message-301',
        plaintext: 'v3 maxfiy xabar',
        sender: alice,
        recipientDevices: [bob.publicKey],
      );
      expect(payload, startsWith('${PqcV3Wire.privatePrefix}:'));
      final envelope = PqcV3Envelope.decode(payload);
      expect(envelope.wraps.map((item) => item.deviceId).toSet(), {
        'alice-phone',
        'bob-tablet',
      });

      final received = await engine.decryptPrivate(
        conversation: conversation,
        payload: payload,
        localKeysets: [bob],
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect((received as PqcDecoded).plaintext, 'v3 maxfiy xabar');

      final sentHistory = await engine.decryptPrivate(
        conversation: conversation,
        payload: payload,
        localKeysets: [alice],
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect((sentHistory as PqcDecoded).plaintext, 'v3 maxfiy xabar');
    });

    test('uses a retained historical keyset after device rotation', () async {
      final payload = await engine.private.encrypt(
        conversation: conversation,
        messageId: 'message-rotation',
        plaintext: 'old v3 history',
        sender: alice,
        recipientDevices: [bob.publicKey],
      );
      final result = await engine.decryptPrivate(
        conversation: conversation,
        payload: payload,
        localKeysets: [bobReplacement, bob],
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect((result as PqcDecoded).plaintext, 'old v3 history');
    });

    test('rejects wrong binding, missing key and untrusted sender', () async {
      final payload = await engine.private.encrypt(
        conversation: conversation,
        messageId: 'message-binding',
        plaintext: 'bound to one conversation',
        sender: alice,
        recipientDevices: [bob.publicKey],
      );
      final wrongConversation = await engine.decryptPrivate(
        conversation: const PqcConversation(id: 302, type: 'private'),
        payload: payload,
        localKeysets: [bob],
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect(
        (wrongConversation as PqcDecodeError).failure,
        PqcDecodeFailure.bindingMismatch,
      );

      final missing = await engine.decryptPrivate(
        conversation: conversation,
        payload: payload,
        localKeysets: [carol],
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect((missing as PqcDecodeError).failure, PqcDecodeFailure.keyMissing);

      final untrusted = await engine.decryptPrivate(
        conversation: conversation,
        payload: payload,
        localKeysets: [bob],
        trustedSigningKeysByDevice: const {},
      );
      expect(
        (untrusted as PqcDecodeError).failure,
        PqcDecodeFailure.untrustedSender,
      );
    });

    test(
      'rejects ciphertext, signature and recipient-wrap tampering',
      () async {
        final payload = await engine.private.encrypt(
          conversation: conversation,
          messageId: 'message-tamper',
          plaintext: 'tamper protected',
          sender: alice,
          recipientDevices: [bob.publicKey],
        );
        final document = _v3Document(payload);
        document['ciphertext'] = '${document['ciphertext']}AA';
        await _expectCorrupted(
          engine,
          conversation,
          _v3Payload(document, isGroup: false),
          bob,
          alice,
        );

        final signatureDocument = _v3Document(payload);
        signatureDocument['signature'] = base64Encode(List<int>.filled(16, 0));
        await _expectCorrupted(
          engine,
          conversation,
          _v3Payload(signatureDocument, isGroup: false),
          bob,
          alice,
        );

        final duplicateWrapDocument = _v3Document(payload);
        final wraps = List<Map<String, dynamic>>.from(
          (duplicateWrapDocument['wraps'] as List).map(
            (item) => Map<String, dynamic>.from(item as Map),
          ),
        );
        wraps.add(Map<String, dynamic>.from(wraps.first));
        duplicateWrapDocument['wraps'] = wraps;
        // The old signature no longer validates. Re-sign it to prove the
        // duplicate-recipient invariant is independently enforced.
        final unsigned = Map<String, dynamic>.from(duplicateWrapDocument)
          ..remove('signature');
        duplicateWrapDocument['signature'] = engine.primitives.sign(
          message: utf8.encode(jsonEncode(unsigned)),
          secretKeyBase64: alice.signingSecretKeyBase64,
        );
        await _expectCorrupted(
          engine,
          conversation,
          _v3Payload(duplicateWrapDocument, isGroup: false),
          bob,
          alice,
        );
      },
    );
  });

  group('PQCv3 group codec', () {
    const conversation = PqcConversation(id: 401, type: 'group');

    test(
      'covers members, decrypts and reports authenticated group metadata',
      () async {
        final payload = await engine.group.encrypt(
          conversation: conversation,
          messageId: 'group-401',
          plaintext: 'v3 guruh xabari',
          sender: alice,
          memberDevices: [bob.publicKey, carol.publicKey],
        );
        final metadata = engine.inspectGroup(payload);
        expect(metadata?.conversationId, conversation.id);
        expect(metadata?.conversationType, 'group');
        expect(metadata?.epochId, isEmpty);

        final result = await engine.decryptGroup(
          conversation: conversation,
          payload: payload,
          epochsById: const {},
          localKeysets: [bob],
          trustedSigningKeysByDevice: _trust(alice),
        );
        expect((result as PqcDecoded).plaintext, 'v3 guruh xabari');
      },
    );

    test('rejects group payload in a private conversation', () async {
      final payload = await engine.group.encrypt(
        conversation: conversation,
        messageId: 'group-binding',
        plaintext: 'privatega tushmasin',
        sender: alice,
        memberDevices: [bob.publicKey],
      );
      final result = await engine.decryptGroup(
        conversation: const PqcConversation(id: 401, type: 'private'),
        payload: payload,
        epochsById: const {},
        localKeysets: [bob],
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect(
        (result as PqcDecodeError).failure,
        PqcDecodeFailure.bindingMismatch,
      );
    });

    test('requires complete host-supplied group member coverage', () {
      expect(
        () => engine.group.encrypt(
          conversation: conversation,
          messageId: 'missing-member',
          plaintext: 'member cover',
          sender: alice,
          memberDevices: [bob.publicKey],
          expectedMemberDevices: [bob.publicKey, carol.publicKey],
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('membership rekey keeps old history for old members only', () async {
      final oldPayload = await engine.group.encrypt(
        conversation: conversation,
        messageId: 'before-member-change',
        plaintext: 'old membership',
        sender: alice,
        memberDevices: [bob.publicKey, carol.publicKey],
        expectedMemberDevices: [bob.publicKey, carol.publicKey],
      );
      final newPayload = await engine.group.encrypt(
        conversation: conversation,
        messageId: 'after-member-change',
        plaintext: 'new membership',
        sender: alice,
        memberDevices: [bob.publicKey],
        expectedMemberDevices: [bob.publicKey],
      );
      Future<PqcDecodeResult> decryptFor(
        String payload,
        PqcDeviceKeyset recipient,
      ) => engine.decryptGroup(
        conversation: conversation,
        payload: payload,
        epochsById: const {},
        localKeysets: [recipient],
        trustedSigningKeysByDevice: _trust(alice),
      );

      expect(
        (await decryptFor(oldPayload, bob) as PqcDecoded).plaintext,
        'old membership',
      );
      expect(
        (await decryptFor(newPayload, bob) as PqcDecoded).plaintext,
        'new membership',
      );
      expect(
        (await decryptFor(oldPayload, carol) as PqcDecoded).plaintext,
        'old membership',
      );
      final removed = await decryptFor(newPayload, carol);
      expect((removed as PqcDecodeError).failure, PqcDecodeFailure.keyMissing);
    });
  });

  group('PQCv3 attachment codec', () {
    test('V3 attachment envelope rejects malformed wrap entries', () {
      final document = const PqcV3AttachmentEnvelope(
        attachmentId: 'strict-attachment',
        conversationId: 1,
        conversationType: 'private',
        senderDeviceId: 'sender',
        senderKeysetId: 'sender-keyset',
        signingPublicKey: 'signing-key',
        attachment: PqcV3EncryptedAttachment(
          filename: 'file.bin',
          mimeType: 'application/octet-stream',
          sizeBytes: 1,
          ciphertext: 'ciphertext',
        ),
        wraps: [
          PqcV3RecipientWrap(
            deviceId: 'recipient',
            keysetId: 'recipient-keyset',
            kemCiphertext: 'kem',
            wrappedKey: 'wrap',
          ),
        ],
      ).toJson();
      document['wraps'] = [...(document['wraps'] as List), 42];

      expect(
        () => PqcV3AttachmentEnvelope.decode(_v3AttachmentPayload(document)),
        throwsA(isA<FormatException>()),
      );
    });

    test('authenticates bytes and immutable metadata', () async {
      final key = engine.attachment.generateContentKey();
      final encrypted = await engine.attachment.encrypt(
        bytes: utf8.encode('PDF/audio/image byte payload'),
        filename: 'hisobot.pdf',
        mimeType: 'application/pdf',
        contentKey: key,
      );
      final clear = await engine.attachment.decrypt(
        attachment: encrypted,
        contentKey: key,
      );
      expect(utf8.decode(clear), 'PDF/audio/image byte payload');

      final changedMetadata = PqcV3EncryptedAttachment(
        filename: 'boshqa.pdf',
        mimeType: encrypted.mimeType,
        sizeBytes: encrypted.sizeBytes,
        ciphertext: encrypted.ciphertext,
      );
      await expectLater(
        engine.attachment.decrypt(attachment: changedMetadata, contentKey: key),
        throwsA(anything),
      );
    });

    test('wraps the attachment key for sender and recipient devices', () async {
      const conversation = PqcConversation(id: 451, type: 'private');
      final payload = await engine.attachment.encryptForRecipients(
        attachmentId: 'attachment-451',
        conversation: conversation,
        bytes: utf8.encode('recipient addressed attachment'),
        filename: 'hisobot.pdf',
        mimeType: 'application/pdf',
        sender: alice,
        recipientDevices: [bob.publicKey],
      );
      final recipient = await engine.attachment.decryptForRecipient(
        conversation: conversation,
        payload: payload,
        localKeysets: [bob],
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect(utf8.decode(recipient.bytes), 'recipient addressed attachment');
      expect(recipient.filename, 'hisobot.pdf');

      final sentHistory = await engine.attachment.decryptForRecipient(
        conversation: conversation,
        payload: payload,
        localKeysets: [alice],
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect(utf8.decode(sentHistory.bytes), 'recipient addressed attachment');

      await expectLater(
        engine.attachment.decryptForRecipient(
          conversation: conversation,
          payload: payload,
          localKeysets: [carol],
          trustedSigningKeysByDevice: _trust(alice),
        ),
        throwsA(isA<PqcV3AttachmentKeyMissingException>()),
      );
    });

    test('restores a missing V3 attachment keyset after reinstall', () async {
      const accountId = 'v3-attachment-reinstall';
      const conversation = PqcConversation(id: 452, type: 'private');
      const recoveryKey = _FixedRecoveryKeyProvider(73);
      final transport = PqcMemoryRecoveryRepository();
      final sourceVault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final sourceRecovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: sourceVault,
        transport: transport,
        keyProvider: recoveryKey,
      );
      final recipient = engine.generateDeviceKeyset('attachment-tablet');
      await sourceVault.saveDeviceKeyset(
        accountId: accountId,
        keyset: recipient,
        makeCurrent: true,
      );
      await sourceRecovery.synchronize(accountId);
      final payload = await engine.attachment.encryptForRecipients(
        attachmentId: 'restore-attachment',
        conversation: conversation,
        bytes: utf8.encode('restored attachment bytes'),
        filename: 'restore.pdf',
        mimeType: 'application/pdf',
        sender: alice,
        recipientDevices: [recipient.publicKey],
      );

      final reinstalledVault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final reinstalledRecovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: reinstalledVault,
        transport: transport,
        keyProvider: recoveryKey,
      );
      final retry = PqcV3AttachmentDecryptRetryCoordinator(
        vault: reinstalledVault,
        recovery: reinstalledRecovery,
        healthMonitor: reinstalledRecovery.healthMonitor,
      );
      final restored = await retry.decrypt(
        accountId: accountId,
        conversation: conversation,
        payload: payload,
        codec: engine.attachment,
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect(utf8.decode(restored.bytes), 'restored attachment bytes');
      expect(
        (await reinstalledVault.readCurrentDeviceKeyset(accountId))?.keysetId,
        recipient.keysetId,
      );
    });
  });

  test(
    'V3 private and group history restore automatically after reinstall',
    () async {
      const accountId = 'v3-reinstall-account';
      const privateConversation = PqcConversation(id: 501, type: 'private');
      const groupConversation = PqcConversation(id: 502, type: 'group');
      final transport = PqcMemoryRecoveryRepository();
      const recoveryKey = _FixedRecoveryKeyProvider(71);
      final sourceVault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final sourceRecovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: sourceVault,
        transport: transport,
        keyProvider: recoveryKey,
      );
      final recipient = engine.generateDeviceKeyset('restored-tablet');
      await sourceVault.saveDeviceKeyset(
        accountId: accountId,
        keyset: recipient,
        makeCurrent: true,
      );
      await sourceRecovery.synchronize(accountId);
      final privatePayload = await engine.private.encrypt(
        conversation: privateConversation,
        messageId: 'private-reinstall',
        plaintext: 'private restored',
        sender: alice,
        recipientDevices: [recipient.publicKey],
      );
      final groupPayload = await engine.group.encrypt(
        conversation: groupConversation,
        messageId: 'group-reinstall',
        plaintext: 'group restored',
        sender: alice,
        memberDevices: [recipient.publicKey],
      );

      final reinstalledVault = PqcIntegrityKeyVault(
        allowInsecureStoreForTesting: true,
        store: PqcMemoryAtomicStore(),
      );
      final reinstalledRecovery = PqcRecoveryCoordinator(
        allowUnauthenticatedRecoveryForTesting: true,
        vault: reinstalledVault,
        transport: transport,
        keyProvider: recoveryKey,
      );
      final retry = PqcDecryptRetryCoordinator(
        manager: PqcEngineManager(
          decoders: [PqcV2CompatibilityDecoder(), engine],
          activeWriter: engine,
          writerEnabled: true,
          releaseProfile: PqcReleaseProfiles.v3,
        ),
        vault: reinstalledVault,
        recovery: reinstalledRecovery,
        healthMonitor: reinstalledRecovery.healthMonitor,
      );
      final privateResult = await retry.decryptPrivate(
        accountId: accountId,
        conversation: privateConversation,
        payload: privatePayload,
        trustedSigningKeysByDevice: _trust(alice),
      );
      final groupResult = await retry.decryptGroup(
        accountId: accountId,
        conversation: groupConversation,
        payload: groupPayload,
        trustedSigningKeysByDevice: _trust(alice),
      );
      expect((privateResult as PqcDecoded).plaintext, 'private restored');
      expect((groupResult as PqcDecoded).plaintext, 'group restored');
    },
  );
}

class _FixedRecoveryKeyProvider implements PqcRecoveryKeyProvider {
  const _FixedRecoveryKeyProvider(this.seed);

  final int seed;

  @override
  Future<List<int>> recoveryKey(String accountId) async =>
      List<int>.generate(32, (index) => (seed + index) & 0xff);
}

Map<String, Set<String>> _trust(PqcDeviceKeyset keyset) => {
  keyset.deviceId: {keyset.signingPublicKeyBase64},
};

Map<String, dynamic> _v3Document(String payload) {
  final prefix = payload.startsWith('${PqcV3Wire.groupPrefix}:')
      ? PqcV3Wire.groupPrefix
      : PqcV3Wire.privatePrefix;
  final encoded = payload.substring(prefix.length + 1);
  final padded = encoded.padRight(
    encoded.length + ((4 - encoded.length % 4) % 4),
    '=',
  );
  return Map<String, dynamic>.from(
    jsonDecode(utf8.decode(base64Url.decode(padded))) as Map,
  );
}

String _v3Payload(Map<String, dynamic> document, {required bool isGroup}) =>
    '${isGroup ? PqcV3Wire.groupPrefix : PqcV3Wire.privatePrefix}:${base64UrlEncode(utf8.encode(jsonEncode(document)))}';

String _v3AttachmentPayload(Map<String, dynamic> document) =>
    '${PqcV3AttachmentEnvelope.prefix}:${base64UrlEncode(utf8.encode(jsonEncode(document)))}';

Future<void> _expectCorrupted(
  PqcV3Engine engine,
  PqcConversation conversation,
  String payload,
  PqcDeviceKeyset recipient,
  PqcDeviceKeyset sender,
) async {
  final result = await engine.decryptPrivate(
    conversation: conversation,
    payload: payload,
    localKeysets: [recipient],
    trustedSigningKeysByDevice: _trust(sender),
  );
  expect((result as PqcDecodeError).failure, PqcDecodeFailure.corrupted);
}
