import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'crypto_utils.dart';
import 'models.dart';
import 'primitives.dart';
import 'v3_attachment_codec.dart';
import 'v3_envelope.dart';

/// Manifest for a chunked, streaming V3 encrypted attachment.
///
/// Ensures constant RAM usage regardless of file size (e.g. 100 MB or 2 GB file
/// uses only chunk-sized buffer in memory, e.g. 64 KB).
class PqcV3ChunkedAttachmentManifest {
  const PqcV3ChunkedAttachmentManifest({
    required this.attachmentId,
    required this.filename,
    required this.mimeType,
    required this.totalSizeBytes,
    required this.chunkSizeBytes,
    required this.totalChunks,
    required this.plaintextSha256,
    required this.conversationId,
    required this.conversationType,
    required this.senderDeviceId,
    required this.senderKeysetId,
    required this.signingPublicKey,
    required this.wraps,
    this.signature,
  });

  static const defaultChunkSize = 64 * 1024; // 64 KB chunks
  static const manifestPrefix = 'manifest:attachment:v3';

  final String attachmentId;
  final String filename;
  final String mimeType;
  final int totalSizeBytes;
  final int chunkSizeBytes;
  final int totalChunks;
  final String plaintextSha256;
  final int conversationId;
  final String conversationType;
  final String senderDeviceId;
  final String senderKeysetId;
  final String signingPublicKey;
  final List<PqcV3RecipientWrap> wraps;
  final String? signature;

  Map<String, dynamic> toJson({bool includeSignature = true}) => {
    'prefix': manifestPrefix,
    'attachment_id': attachmentId,
    'filename': filename,
    'mime_type': mimeType,
    'total_size_bytes': totalSizeBytes,
    'chunk_size_bytes': chunkSizeBytes,
    'total_chunks': totalChunks,
    'plaintext_sha256': plaintextSha256,
    'conversation_id': conversationId,
    'conversation_type': conversationType,
    'sender_device_id': senderDeviceId,
    'sender_keyset_id': senderKeysetId,
    'signing_public_key': signingPublicKey,
    'wraps': wraps.map((w) => w.toJson()).toList(),
    if (includeSignature && signature != null) 'signature': signature,
  };

  String unsignedCanonicalJson() => canonicalJsonEncode(
    toJson(includeSignature: false),
  );

  String encode() =>
      '$manifestPrefix:${base64UrlEncode(utf8.encode(canonicalJsonEncode(toJson())))}';

  static PqcV3ChunkedAttachmentManifest decode(String payload) {
    if (!payload.startsWith('$manifestPrefix:')) {
      throw const FormatException('Unsupported V3 chunked manifest prefix.');
    }
    final encoded = payload.substring(manifestPrefix.length + 1);
    final padded = encoded.padRight(
      encoded.length + ((4 - encoded.length % 4) % 4),
      '=',
    );
    final decoded = jsonDecode(
      utf8.decode(base64Url.decode(padded), allowMalformed: false),
    );
    if (decoded is! Map) {
      throw const FormatException('Invalid V3 chunked manifest document.');
    }
    final map = Map<String, dynamic>.from(decoded);
    final wrapsList = map['wraps'];
    if (wrapsList is! List) {
      throw const FormatException('Manifest recipient wraps must be a list.');
    }
    return PqcV3ChunkedAttachmentManifest(
      attachmentId: map['attachment_id'] as String? ?? '',
      filename: map['filename'] as String? ?? '',
      mimeType: map['mime_type'] as String? ?? '',
      totalSizeBytes: map['total_size_bytes'] as int? ?? 0,
      chunkSizeBytes: map['chunk_size_bytes'] as int? ?? defaultChunkSize,
      totalChunks: map['total_chunks'] as int? ?? 0,
      plaintextSha256: map['plaintext_sha256'] as String? ?? '',
      conversationId: map['conversation_id'] as int? ?? 0,
      conversationType: map['conversation_type'] as String? ?? '',
      senderDeviceId: map['sender_device_id'] as String? ?? '',
      senderKeysetId: map['sender_keyset_id'] as String? ?? '',
      signingPublicKey: map['signing_public_key'] as String? ?? '',
      wraps: wrapsList
          .map((item) => PqcV3RecipientWrap.fromJson(Map<String, dynamic>.from(item as Map)))
          .toList(growable: false),
      signature: map['signature'] as String?,
    );
  }
}

/// Encrypted chunk descriptor containing binary ciphertext and authenticated MAC.
class PqcV3EncryptedChunk {
  PqcV3EncryptedChunk({
    required this.chunkIndex,
    required List<int> ciphertextWithMacAndNonce,
  }) : bytes = Uint8List.fromList(ciphertextWithMacAndNonce);

  final int chunkIndex;
  final Uint8List bytes;
}

/// High-performance, streaming post-quantum attachment codec.
///
/// Solves Out-Of-Memory (OOM) crashes by streaming byte chunks in fixed memory
/// windows (64 KB). The encryption key is shared across chunks using unique
/// chunk nonces, and wrapped for recipient devices via ML-KEM.
class PqcV3ChunkedAttachmentCodec {
  PqcV3ChunkedAttachmentCodec(this._primitives);

  final PqcPrimitiveSuite _primitives;

  /// Creates a signed attachment manifest with per-device ML-KEM key wraps.
  Future<({PqcV3ChunkedAttachmentManifest manifest, Uint8List contentKey})>
      createManifest({
    required String attachmentId,
    required PqcConversation conversation,
    required String filename,
    required String mimeType,
    required int totalSizeBytes,
    required String plaintextSha256,
    required PqcDeviceKeyset sender,
    required Iterable<PqcDevicePublicKey> recipientDevices,
    int chunkSizeBytes = PqcV3ChunkedAttachmentManifest.defaultChunkSize,
  }) async {
    if (attachmentId.trim().isEmpty) {
      throw ArgumentError.value(attachmentId, 'attachmentId', 'Must not be empty.');
    }
    if (totalSizeBytes < 0) {
      throw ArgumentError.value(totalSizeBytes, 'totalSizeBytes', 'Must be non-negative.');
    }
    final totalChunks = totalSizeBytes == 0
        ? 0
        : ((totalSizeBytes + chunkSizeBytes - 1) ~/ chunkSizeBytes);

    final recipients = <String, PqcDevicePublicKey>{};
    for (final recipient in recipientDevices) {
      recipients['${recipient.deviceId}|${recipient.keysetId}'] = recipient;
    }
    recipients['${sender.deviceId}|${sender.keysetId}'] = sender.publicKey;

    final contentKey = _primitives.randomBytes(32);
    final wraps = <PqcV3RecipientWrap>[];

    for (final recipient in recipients.values) {
      final kem = _primitives.encapsulate(recipient.kemPublicKeyBase64);
      try {
        final box = await _primitives.encryptAead(
          plaintext: contentKey,
          key: kem.sharedSecret,
          nonce: _primitives.randomBytes(12),
          associatedData: utf8.encode('$attachmentId:${recipient.deviceId}'),
        );
        wraps.add(
          PqcV3RecipientWrap(
            deviceId: recipient.deviceId,
            keysetId: recipient.keysetId,
            kemCiphertext: kem.ciphertextBase64,
            wrappedKey: base64Encode([...box.nonce, ...box.ciphertext, ...box.mac]),
          ),
        );
      } finally {
        kem.zeroize();
      }
    }

    final unsigned = PqcV3ChunkedAttachmentManifest(
      attachmentId: attachmentId,
      filename: filename,
      mimeType: mimeType,
      totalSizeBytes: totalSizeBytes,
      chunkSizeBytes: chunkSizeBytes,
      totalChunks: totalChunks,
      plaintextSha256: plaintextSha256,
      conversationId: conversation.id,
      conversationType: conversation.type,
      senderDeviceId: sender.deviceId,
      senderKeysetId: sender.keysetId,
      signingPublicKey: sender.signingPublicKeyBase64,
      wraps: wraps,
    );

    final signature = _primitives.sign(
      message: utf8.encode(unsigned.unsignedCanonicalJson()),
      secretKeyBase64: sender.signingSecretKeyBase64,
    );

    final signedManifest = PqcV3ChunkedAttachmentManifest(
      attachmentId: unsigned.attachmentId,
      filename: unsigned.filename,
      mimeType: unsigned.mimeType,
      totalSizeBytes: unsigned.totalSizeBytes,
      chunkSizeBytes: unsigned.chunkSizeBytes,
      totalChunks: unsigned.totalChunks,
      plaintextSha256: unsigned.plaintextSha256,
      conversationId: unsigned.conversationId,
      conversationType: unsigned.conversationType,
      senderDeviceId: unsigned.senderDeviceId,
      senderKeysetId: unsigned.senderKeysetId,
      signingPublicKey: unsigned.signingPublicKey,
      wraps: unsigned.wraps,
      signature: signature,
    );

    return (manifest: signedManifest, contentKey: contentKey);
  }

  /// Encrypts an individual chunk of data with authenticated index binding.
  Future<PqcV3EncryptedChunk> encryptChunk({
    required List<int> chunkPlaintext,
    required int chunkIndex,
    required String attachmentId,
    required List<int> contentKey,
  }) async {
    final nonce = _deriveChunkNonce(attachmentId, chunkIndex);
    final aad = utf8.encode('$attachmentId:chunk:$chunkIndex');

    final box = await _primitives.encryptAead(
      plaintext: chunkPlaintext,
      key: contentKey,
      nonce: nonce,
      associatedData: aad,
    );

    return PqcV3EncryptedChunk(
      chunkIndex: chunkIndex,
      ciphertextWithMacAndNonce: [...box.nonce, ...box.ciphertext, ...box.mac],
    );
  }

  /// Decrypts an individual chunk of data and verifies its authenticated index.
  Future<Uint8List> decryptChunk({
    required PqcV3EncryptedChunk chunk,
    required String attachmentId,
    required List<int> contentKey,
  }) async {
    final bytes = chunk.bytes;
    if (bytes.length < 28) {
      throw const FormatException('Encrypted chunk payload is too short.');
    }
    final nonce = bytes.sublist(0, 12);
    final ciphertext = bytes.sublist(12, bytes.length - 16);
    final mac = bytes.sublist(bytes.length - 16);
    final aad = utf8.encode('$attachmentId:chunk:${chunk.chunkIndex}');

    return _primitives.decryptAead(
      box: PqcAeadBox(nonce: nonce, ciphertext: ciphertext, mac: mac),
      key: contentKey,
      associatedData: aad,
    );
  }

  /// Resolves the content key from the manifest for the local recipient keyset.
  Future<Uint8List> resolveContentKey({
    required PqcV3ChunkedAttachmentManifest manifest,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    // 1. Verify manifest signature
    final trusted = trustedSigningKeysByDevice[manifest.senderDeviceId];
    if (trusted == null || !trusted.contains(manifest.signingPublicKey)) {
      throw const FormatException('Chunked manifest sender is not trusted.');
    }
    if (manifest.signature == null ||
        !_primitives.verify(
          message: utf8.encode(manifest.unsignedCanonicalJson()),
          signatureBase64: manifest.signature!,
          publicKeyBase64: manifest.signingPublicKey,
        )) {
      throw const FormatException('Chunked manifest signature verification failed.');
    }

    // 2. Locate matching recipient wrap
    PqcDeviceKeyset? selectedKeyset;
    PqcV3RecipientWrap? selectedWrap;
    for (final keyset in localKeysets) {
      for (final wrap in manifest.wraps) {
        if (wrap.deviceId == keyset.deviceId && wrap.keysetId == keyset.keysetId) {
          selectedKeyset = keyset;
          selectedWrap = wrap;
          break;
        }
      }
      if (selectedWrap != null) break;
    }

    if (selectedKeyset == null || selectedWrap == null) {
      throw const PqcV3AttachmentKeyMissingException();
    }

    // 3. Decapsulate content key
    final sharedSecret = _primitives.decapsulate(
      ciphertextBase64: selectedWrap.kemCiphertext,
      secretKeyBase64: selectedKeyset.kemSecretKeyBase64,
    );

    try {
      final packed = base64Decode(selectedWrap.wrappedKey);
      final box = PqcAeadBox(
        nonce: packed.sublist(0, 12),
        ciphertext: packed.sublist(12, packed.length - 16),
        mac: packed.sublist(packed.length - 16),
      );
      return await _primitives.decryptAead(
        box: box,
        key: sharedSecret,
        associatedData: utf8.encode('${manifest.attachmentId}:${selectedKeyset.deviceId}'),
      );
    } finally {
      secureZero(sharedSecret);
    }
  }

  /// Deterministically derives a 12-byte nonce for a chunk to prevent reuse.
  Uint8List _deriveChunkNonce(String attachmentId, int chunkIndex) {
    final digest = crypto.sha256.convert(
      utf8.encode('$attachmentId:nonce:$chunkIndex'),
    );
    return Uint8List.fromList(digest.bytes.sublist(0, 12));
  }
}
