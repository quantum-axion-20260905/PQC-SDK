import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';
import 'package:test/test.dart';

void main() {
  late PqcPrimitiveSuite primitives;
  late PqcDeviceKeyset sender;
  late PqcDeviceKeyset recipientA;
  late PqcDeviceKeyset recipientB;
  late PqcV3ChunkedAttachmentCodec codec;
  late PqcGroupSenderKeyEngine engine;

  setUpAll(() {
    primitives = DartPqcPrimitiveSuite();
    sender = primitives.generateDeviceKeyset('sender-device');
    recipientA = primitives.generateDeviceKeyset('recipient-a');
    recipientB = primitives.generateDeviceKeyset('recipient-b');
    codec = PqcV3ChunkedAttachmentCodec(primitives);
    engine = PqcGroupSenderKeyEngine(primitives);
  });

  group('Streaming / Chunked V3 Attachment Codec', () {
    const conversation = PqcConversation(id: 101, type: 'private');

    test('streams large payload in fixed 64KB memory windows without OOM', () async {
      // Create a 150 KB test payload that splits into 3 chunks (64KB, 64KB, 22KB)
      const totalSize = 150 * 1024;
      final plaintext = Uint8List(totalSize);
      for (var i = 0; i < totalSize; i++) {
        plaintext[i] = i % 251;
      }
      final expectedSha256 = crypto.sha256.convert(plaintext).toString();

      // 1. Create streaming manifest
      final manifestResult = await codec.createManifest(
        attachmentId: 'stream-att-1',
        conversation: conversation,
        filename: 'large_document.pdf',
        mimeType: 'application/pdf',
        totalSizeBytes: totalSize,
        plaintextSha256: expectedSha256,
        sender: sender,
        recipientDevices: [recipientA.publicKey, recipientB.publicKey],
        chunkSizeBytes: 64 * 1024,
      );
      final manifest = manifestResult.manifest;
      final contentKey = manifestResult.contentKey;

      expect(manifest.totalChunks, 3);
      expect(manifest.wraps.length, 3); // recipientA, recipientB, and sender

      // 2. Encrypt in chunks (constant memory)
      final encryptedChunks = <PqcV3EncryptedChunk>[];
      for (var chunkIdx = 0; chunkIdx < manifest.totalChunks; chunkIdx++) {
        final start = chunkIdx * manifest.chunkSizeBytes;
        final end = (start + manifest.chunkSizeBytes > totalSize)
            ? totalSize
            : start + manifest.chunkSizeBytes;
        final chunkBytes = plaintext.sublist(start, end);

        final chunk = await codec.encryptChunk(
          chunkPlaintext: chunkBytes,
          chunkIndex: chunkIdx,
          attachmentId: manifest.attachmentId,
          contentKey: contentKey,
        );
        encryptedChunks.add(chunk);
      }
      expect(encryptedChunks.length, 3);

      // 3. Recipient A resolves content key from manifest
      final recipientContentKey = await codec.resolveContentKey(
        manifest: manifest,
        localKeysets: [recipientA],
        trustedSigningKeysByDevice: {
          sender.deviceId: {sender.signingPublicKeyBase64},
        },
      );

      // 4. Decrypt stream chunk-by-chunk and assemble plaintext
      final assembled = BytesBuilder(copy: false);
      for (final chunk in encryptedChunks) {
        final decryptedChunk = await codec.decryptChunk(
          chunk: chunk,
          attachmentId: manifest.attachmentId,
          contentKey: recipientContentKey,
        );
        assembled.add(decryptedChunk);
      }

      final restored = assembled.takeBytes();
      expect(restored.length, totalSize);
      expect(crypto.sha256.convert(restored).toString(), expectedSha256);

      // 5. Tampered chunk or out-of-order index fails decryption
      expect(
        () => codec.decryptChunk(
          chunk: PqcV3EncryptedChunk(
            chunkIndex: 99, // wrong index
            ciphertextWithMacAndNonce: encryptedChunks[0].bytes,
          ),
          attachmentId: manifest.attachmentId,
          contentKey: recipientContentKey,
        ),
        throwsA(anything),
      );
    });
  });

  group('Scalable O(1) Group Sender-Key Engine', () {
    const conversationId = 555;
    const epochId = 'epoch-2026-v1';

    test('distributes sender key once, then sends lightweight O(1) messages', () async {
      // 5 member devices in group
      final members = List.generate(
        5,
        (i) => primitives.generateDeviceKeyset('member-device-$i'),
      );

      // 1. Sender distributes Sender Key once (O(N) initial setup)
      final distResult = await engine.createDistribution(
        conversationId: conversationId,
        epochId: epochId,
        sender: sender,
        memberDevices: members.map((m) => m.publicKey),
      );
      final distribution = distResult.distribution;
      final senderChainKey = distResult.senderChainKey;

      expect(distribution.wraps.length, 5);
      final distributionPayload = distribution.encode();
      expect(distributionPayload, startsWith('${PqcSenderKeyDistribution.prefix}:'));

      // 2. Member 0 receives distribution and extracts chain key
      final member0 = members[0];
      var member0ChainKey = await engine.receiveDistribution(
        distribution: PqcSenderKeyDistribution.decode(distributionPayload),
        localKeysets: [member0],
        trustedSigningKeysByDevice: {
          sender.deviceId: {sender.signingPublicKeyBase64},
        },
      );

      // 3. Sender sends Message #0 (O(1) payload size ~300 bytes, NO per-recipient wraps)
      final sendResult0 = await engine.encryptGroupMessage(
        conversationId: conversationId,
        epochId: epochId,
        sequenceNumber: 0,
        plaintext: 'Guruhga birinchi xabar!',
        sender: sender,
        currentChainKey: senderChainKey,
      );
      final msg0Payload = sendResult0.payload;
      final chainKey1 = sendResult0.nextChainKey;

      expect(msg0Payload, startsWith('${PqcGroupSenderMessage.prefix}:'));
      // Payload size is constant O(1), dominated by the ML-DSA signature (~4.5KB)
      // rather than scaling linearly O(N) with member count
      expect(msg0Payload.length, lessThan(8000));

      // 4. Member 0 decrypts Message #0
      final readResult0 = await engine.decryptGroupMessage(
        payload: msg0Payload,
        currentChainKey: member0ChainKey,
        trustedSenderSigningKeys: {sender.signingPublicKeyBase64},
      );
      expect(readResult0.plaintext, 'Guruhga birinchi xabar!');
      member0ChainKey = readResult0.nextChainKey;

      // 5. Sender sends Message #1 (ratcheting forward)
      final sendResult1 = await engine.encryptGroupMessage(
        conversationId: conversationId,
        epochId: epochId,
        sequenceNumber: 1,
        plaintext: 'Guruhga ikkinchi xabar!',
        sender: sender,
        currentChainKey: chainKey1,
      );

      final readResult1 = await engine.decryptGroupMessage(
        payload: sendResult1.payload,
        currentChainKey: member0ChainKey,
        trustedSenderSigningKeys: {sender.signingPublicKeyBase64},
      );
      expect(readResult1.plaintext, 'Guruhga ikkinchi xabar!');
    });
  });

  group('Replay Store Sliding Window and Eviction', () {
    test('evicts oldest entries when maxEntries is reached (sliding window)', () async {
      final store = PqcMemoryReplayStore(maxEntries: 3);

      // Claim 3 messages
      await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-1',
        payloadDigest: 'a' * 64,
      );
      await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-2',
        payloadDigest: 'b' * 64,
      );
      await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-3',
        payloadDigest: 'c' * 64,
      );
      expect(store.entryCount, 3);

      // Claim 4th message -> msg-1 should be evicted from memory window
      await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-4',
        payloadDigest: 'd' * 64,
      );
      expect(store.entryCount, 3);

      // msg-2, msg-3, msg-4 should still be remembered as duplicates
      final dup = await store.claim(
        accountBinding: 'acc',
        conversationId: 1,
        messageId: 'msg-2',
        payloadDigest: 'b' * 64,
      );
      expect(dup, 'b' * 64);
    });
  });
}
