import 'dart:collection';

import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';
import 'package:test/test.dart';

class _SingleUseIterable<T> extends IterableBase<T> {
  _SingleUseIterable(Iterable<T> values) : _values = List<T>.of(values);

  final List<T> _values;
  bool _wasIterated = false;

  @override
  Iterator<T> get iterator {
    if (_wasIterated) {
      throw StateError('This iterable may only be iterated once.');
    }
    _wasIterated = true;
    return _values.iterator;
  }
}

void main() {
  final engine = PqcV2Engine();
  const capabilities = PqcRemoteCapabilities(
    privateReadPrefixes: {PqcV2Wire.privatePrefix},
    groupReadPrefixes: {PqcV2Wire.groupPrefix},
    privateWritePrefixes: {PqcV2Wire.privatePrefix},
    groupWritePrefixes: {PqcV2Wire.groupPrefix},
    privateAlgorithms: {PqcV2Wire.privateAlgorithm},
    groupAlgorithms: {PqcV2Wire.groupAlgorithm},
    attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
    minimumDecoderVersion: 2,
  );

  test('writer is closed unless explicitly enabled', () {
    final manager = PqcEngineManager(
      decoders: [engine],
      activeWriterId: engine.engineId,
    );
    expect(
      () => manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: capabilities,
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
  });

  test('capability gate allows only advertised format', () {
    final manager = PqcEngineManager(
      decoders: [engine],
      activeWriterId: engine.engineId,
      writerEnabled: true,
    );
    expect(
      manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: capabilities,
      ),
      same(engine),
    );
    expect(
      () => manager.requireWriter(
        kind: PqcConversationKind.group,
        remote: const PqcRemoteCapabilities(
          privateReadPrefixes: {PqcV2Wire.privatePrefix},
          groupReadPrefixes: {},
          privateWritePrefixes: {PqcV2Wire.privatePrefix},
          groupWritePrefixes: {},
          privateAlgorithms: {PqcV2Wire.privateAlgorithm},
          groupAlgorithms: {PqcV2Wire.groupAlgorithm},
          attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
          minimumDecoderVersion: 2,
        ),
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
  });

  test(
    'capability gate rejects a shared prefix without the exact algorithm',
    () {
      final manager = PqcEngineManager(
        decoders: [engine],
        activeWriterId: engine.engineId,
        writerEnabled: true,
      );
      expect(
        () => manager.requireWriter(
          kind: PqcConversationKind.group,
          remote: const PqcRemoteCapabilities(
            privateReadPrefixes: {PqcV2Wire.privatePrefix},
            groupReadPrefixes: {PqcV2Wire.groupPrefix},
            privateWritePrefixes: {PqcV2Wire.privatePrefix},
            groupWritePrefixes: {PqcV2Wire.groupPrefix},
            privateAlgorithms: {PqcV2Wire.privateAlgorithm},
            groupAlgorithms: {},
            attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
            minimumDecoderVersion: 2,
          ),
        ),
        throwsA(isA<PqcCompatibilityException>()),
      );
    },
  );

  test('rejects read/write asymmetry and decoder downgrade', () {
    final manager = PqcEngineManager(
      decoders: [engine],
      activeWriterId: engine.engineId,
      writerEnabled: true,
    );
    expect(
      () => manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: const PqcRemoteCapabilities(
          privateReadPrefixes: {},
          groupReadPrefixes: {PqcV2Wire.groupPrefix},
          privateWritePrefixes: {PqcV2Wire.privatePrefix},
          groupWritePrefixes: {PqcV2Wire.groupPrefix},
          privateAlgorithms: {PqcV2Wire.privateAlgorithm},
          groupAlgorithms: {PqcV2Wire.groupAlgorithm},
          attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
          minimumDecoderVersion: 2,
        ),
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
    expect(
      () => manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: const PqcRemoteCapabilities(
          privateReadPrefixes: {PqcV2Wire.privatePrefix},
          groupReadPrefixes: {PqcV2Wire.groupPrefix},
          privateWritePrefixes: {PqcV2Wire.privatePrefix},
          groupWritePrefixes: {PqcV2Wire.groupPrefix},
          privateAlgorithms: {PqcV2Wire.privateAlgorithm},
          groupAlgorithms: {PqcV2Wire.groupAlgorithm},
          attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
          minimumDecoderVersion: 3,
        ),
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
  });

  test('routes recognized formats and rejects unknown payloads', () {
    final manager = PqcEngineManager(decoders: [engine]);
    expect(
      manager.resolveDecoder(
        kind: PqcConversationKind.private,
        payload: '${PqcV2Wire.privatePrefix}:payload',
      ),
      same(engine),
    );
    expect(
      () => manager.resolveDecoder(
        kind: PqcConversationKind.private,
        payload: 'pqc:v99:payload',
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
  });

  test('rejects duplicate engine ids', () {
    expect(
      () => PqcEngineManager(decoders: [engine, PqcV2Engine()]),
      throwsArgumentError,
    );
  });

  test('rejects a different writer instance with a registered engine id', () {
    expect(
      () => PqcEngineManager(
        decoders: [engine],
        activeWriter: PqcV2Engine(),
        writerEnabled: true,
      ),
      throwsArgumentError,
    );
  });

  test('registers decoders from a single-use iterable', () {
    final manager = PqcEngineManager(
      decoders: _SingleUseIterable([engine]),
      activeWriterId: engine.engineId,
      writerEnabled: true,
    );

    expect(manager.decoders, [same(engine)]);
    expect(
      manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: capabilities,
      ),
      same(engine),
    );
  });

  test('V3 profile retains V2 reader but has only the V3 writer', () {
    final v3 = PqcV3Engine();
    final manager = PqcEngineManager(
      decoders: [PqcV2CompatibilityDecoder(), v3],
      activeWriter: v3,
      writerEnabled: true,
      releaseProfile: PqcReleaseProfiles.v3,
    );
    expect(manager.releaseId, '3.0.0');
    expect(
      manager
          .resolveDecoder(
            kind: PqcConversationKind.private,
            payload: '${PqcV2Wire.privatePrefix}:history',
          )
          .engineId,
      'pqc-v2',
    );
    expect(
      manager.resolveDecoder(
        kind: PqcConversationKind.private,
        payload: '${PqcV3Wire.privatePrefix}:new-message',
      ),
      same(v3),
    );
    final writer = manager.requireWriter(
      kind: PqcConversationKind.private,
      remote: const PqcRemoteCapabilities(
        privateReadPrefixes: {PqcV3Wire.privatePrefix},
        groupReadPrefixes: {PqcV3Wire.groupPrefix},
        privateWritePrefixes: {PqcV3Wire.privatePrefix},
        groupWritePrefixes: {PqcV3Wire.groupPrefix},
        privateAlgorithms: {PqcV3Wire.privateAlgorithm},
        groupAlgorithms: {PqcV3Wire.groupAlgorithm},
        attachmentCipherVersions: {PqcV3Wire.attachmentCipherVersion},
        minimumDecoderVersion: 3,
      ),
    );
    expect(writer, same(v3));
  });

  test(
    'V3 bundle reads V2 history but a V2 decoder rejects V3 payloads',
    () async {
      final bundle = PqcEngineBundles.v3(writerEnabled: true);
      final v3 = bundle.writer as PqcV3Engine;
      final v2 = PqcV2Engine();
      final sender = v3.generateDeviceKeyset('mixed-sender');
      final recipient = v3.generateDeviceKeyset('mixed-recipient');
      const conversation = PqcConversation(id: 87, type: 'private');
      final v3Payload = await v3.private.encrypt(
        conversation: conversation,
        messageId: 'mixed-v3',
        plaintext: 'new wire',
        sender: sender,
        recipientDevices: [recipient.publicKey],
      );
      final legacyAttempt = await v2.decryptPrivate(
        conversation: conversation,
        payload: v3Payload,
        localKeysets: [recipient],
        trustedSigningKeysByDevice: _trust(sender),
      );
      expect(
        (legacyAttempt as PqcDecodeError).failure,
        PqcDecodeFailure.unsupported,
      );

      final v2Payload = await v2.private.encrypt(
        conversation: conversation,
        plaintext: 'frozen wire',
        sender: sender,
        recipientDevices: [recipient.publicKey],
      );
      final reader = bundle.manager.resolveDecoder(
        kind: PqcConversationKind.private,
        payload: v2Payload,
      );
      expect(reader, isA<PqcV2CompatibilityDecoder>());
      final decoded = await reader.decryptPrivate(
        conversation: conversation,
        payload: v2Payload,
        localKeysets: [recipient],
        trustedSigningKeysByDevice: _trust(sender),
      );
      expect((decoded as PqcDecoded).plaintext, 'frozen wire');
    },
  );

  test('V3 bundle keeps its writer closed until the explicit gate opens', () {
    final closed = PqcEngineBundles.v3();
    expect(
      () => closed.manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: _v3Capabilities,
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
    final opened = PqcEngineBundles.v3(writerEnabled: true);
    expect(
      opened.manager.requireWriter(
        kind: PqcConversationKind.group,
        remote: _v3Capabilities,
      ),
      same(opened.writer),
    );
  });

  test('read-only V2 compatibility facade decrypts frozen history', () async {
    final writer = PqcV2Engine();
    final sender = writer.generateDeviceKeyset('compat-sender');
    final recipient = writer.generateDeviceKeyset('compat-recipient');
    final payload = await writer.private.encrypt(
      conversation: const PqcConversation(id: 91, type: 'private'),
      plaintext: 'frozen history',
      sender: sender,
      recipientDevices: [recipient.publicKey],
    );
    final reader = PqcV2CompatibilityDecoder();
    final result = await reader.decryptPrivate(
      conversation: const PqcConversation(id: 91, type: 'private'),
      payload: payload,
      localKeysets: [recipient],
      trustedSigningKeysByDevice: {
        sender.deviceId: {sender.signingPublicKeyBase64},
      },
    );
    expect((result as PqcDecoded).plaintext, 'frozen history');
  });

  test(
    'V2 bundle keeps the authenticated V2 writer and wire profile together',
    () {
      final bundle = PqcEngineBundles.v2(writerEnabled: true);

      expect(bundle.writer, isA<PqcV2Engine>());
      expect(bundle.decoders, hasLength(1));
      expect(bundle.decoders.single, same(bundle.writer));
      expect(bundle.manager.releaseProfile, same(PqcReleaseProfiles.v2));
    },
  );

  test(
    'V2.5 bundle fixes the reader/writer boundary and all V2 wire codecs',
    () async {
      final bundle = PqcEngineBundles.v25(writerEnabled: true);
      final writer = bundle.writer as PqcV25Writer;
      final reader = bundle.decoders.single;
      expect(reader, isA<PqcV2CompatibilityDecoder>());
      expect(reader.engineId, 'pqc-v2');
      expect(writer.engineId, 'pqc-v2.5-writer');
      expect(bundle.manager.releaseProfile, same(PqcReleaseProfiles.v25));

      final sender = writer.generateDeviceKeyset('bundle-sender');
      final recipient = writer.generateDeviceKeyset('bundle-recipient');
      const privateConversation = PqcConversation(id: 92, type: 'private');
      final privatePayload = await writer.private.encrypt(
        conversation: privateConversation,
        plaintext: 'V2.5 private',
        sender: sender,
        recipientDevices: [recipient.publicKey],
      );
      final privateResult = await bundle.manager
          .resolveDecoder(
            kind: PqcConversationKind.private,
            payload: privatePayload,
          )
          .decryptPrivate(
            conversation: privateConversation,
            payload: privatePayload,
            localKeysets: [recipient],
            trustedSigningKeysByDevice: {
              sender.deviceId: {sender.signingPublicKeyBase64},
            },
          );
      expect((privateResult as PqcDecoded).plaintext, 'V2.5 private');

      const groupConversation = PqcConversation(id: 93, type: 'group');
      final epoch = PqcGroupEpoch(
        epochId: 'bundle-epoch',
        secretKeyBytes: writer.primitives.randomBytes(32),
      );
      final groupPayload = await writer.group.encrypt(
        conversation: groupConversation,
        plaintext: 'V2.5 group',
        epoch: epoch,
        sender: sender,
      );
      final groupResult = await bundle.manager
          .resolveDecoder(
            kind: PqcConversationKind.group,
            payload: groupPayload,
          )
          .decryptGroup(
            conversation: groupConversation,
            payload: groupPayload,
            epochsById: {epoch.epochId: epoch},
            trustedSigningKeysByDevice: {
              sender.deviceId: {sender.signingPublicKeyBase64},
            },
          );
      expect((groupResult as PqcDecoded).plaintext, 'V2.5 group');

      final descriptor = writer.attachment.generateDescriptor();
      final encrypted = await writer.attachment.encryptChunk(
        plaintext: [1, 2, 3, 4],
        descriptor: descriptor,
        chunkIndex: 0,
      );
      expect(
        await writer.attachment.decryptChunk(
          ciphertext: encrypted.ciphertext,
          descriptor: descriptor,
          chunkIndex: 0,
        ),
        [1, 2, 3, 4],
      );

      expect(
        bundle.manager.requireWriter(
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        same(writer),
      );
    },
  );
}

Map<String, Set<String>> _trust(PqcDeviceKeyset keyset) => {
  keyset.deviceId: {keyset.signingPublicKeyBase64},
};

const _v3Capabilities = PqcRemoteCapabilities(
  privateReadPrefixes: {PqcV3Wire.privatePrefix},
  groupReadPrefixes: {PqcV3Wire.groupPrefix},
  privateWritePrefixes: {PqcV3Wire.privatePrefix},
  groupWritePrefixes: {PqcV3Wire.groupPrefix},
  privateAlgorithms: {PqcV3Wire.privateAlgorithm},
  groupAlgorithms: {PqcV3Wire.groupAlgorithm},
  attachmentCipherVersions: {PqcV3Wire.attachmentCipherVersion},
  minimumDecoderVersion: 3,
);
