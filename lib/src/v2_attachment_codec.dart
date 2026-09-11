import 'dart:convert';
import 'dart:typed_data';

import 'models.dart';
import 'primitives.dart';

class PqcAttachmentDescriptor {
  const PqcAttachmentDescriptor({
    required this.cipherVersion,
    required this.fileKeyBase64,
    required this.nonceSeedBase64,
    this.conversationEpochId = '',
    this.manifestSequence = 0,
  });

  final String cipherVersion;
  final String fileKeyBase64;
  final String nonceSeedBase64;
  final String conversationEpochId;
  final int manifestSequence;

  Map<String, dynamic> toJson() => {
    'cipher_version': cipherVersion,
    'file_key_base64': fileKeyBase64,
    'nonce_seed_base64': nonceSeedBase64,
    'conversation_epoch_id': conversationEpochId,
    'manifest_sequence': manifestSequence,
  };

  factory PqcAttachmentDescriptor.fromJson(Map<String, dynamic> json) {
    return PqcAttachmentDescriptor(
      cipherVersion: json['cipher_version'] as String? ?? '',
      fileKeyBase64: json['file_key_base64'] as String? ?? '',
      nonceSeedBase64: json['nonce_seed_base64'] as String? ?? '',
      conversationEpochId: json['conversation_epoch_id'] as String? ?? '',
      manifestSequence: json['manifest_sequence'] as int? ?? 0,
    );
  }
}

class PqcAttachmentManifest {
  const PqcAttachmentManifest({
    required this.filename,
    required this.mimeType,
    required this.cipherVersion,
    required this.chunkSize,
    required this.plaintextSize,
    required this.ciphertextSize,
    required this.totalChunks,
    required this.plaintextSha256,
    required this.fileKeyWrap,
    this.conversationEpochId = '',
    this.recoveryManifestSequence = 0,
  });

  final String filename;
  final String mimeType;
  final String cipherVersion;
  final int chunkSize;
  final int plaintextSize;
  final int ciphertextSize;
  final int totalChunks;
  final String plaintextSha256;
  final String fileKeyWrap;
  final String conversationEpochId;
  final int recoveryManifestSequence;

  Map<String, dynamic> canonicalJson() => {
    'filename': filename,
    'mime_type': mimeType,
    'cipher_version': cipherVersion,
    'chunk_size': chunkSize,
    'plaintext_size': plaintextSize,
    'ciphertext_size': ciphertextSize,
    'total_chunks': totalChunks,
    'plaintext_sha256': plaintextSha256,
    'file_key_wrap': fileKeyWrap,
    'conversation_epoch_id': conversationEpochId,
    'recovery_manifest_sequence': recoveryManifestSequence,
  };
}

class PqcAttachmentChunk {
  PqcAttachmentChunk({
    required List<int> ciphertext,
    required this.plaintextLength,
  }) : ciphertext = Uint8List.fromList(ciphertext);

  final Uint8List ciphertext;
  final int plaintextLength;
}

/// Pure byte-oriented PQCv2 attachment crypto.
///
/// File selection, streaming, persistence, upload and retry stay in the host.
/// This keeps the SDK usable on Flutter, server Dart and the web.
class PqcV2AttachmentCodec {
  PqcV2AttachmentCodec(this._primitives);

  final PqcPrimitiveSuite _primitives;

  PqcAttachmentDescriptor generateDescriptor() {
    return PqcAttachmentDescriptor(
      cipherVersion: PqcV2Wire.attachmentCipherVersion,
      fileKeyBase64: base64Encode(_primitives.randomBytes(32)),
      nonceSeedBase64: base64Encode(_primitives.randomBytes(16)),
    );
  }

  Future<PqcAttachmentDescriptor> deriveEpochBoundDescriptor({
    required List<int> conversationEpochSecret,
    required String conversationEpochId,
    required String attachmentId,
    required int manifestSequence,
  }) async {
    if (conversationEpochId.isEmpty ||
        attachmentId.isEmpty ||
        manifestSequence < 0) {
      throw ArgumentError(
        'Epoch id and attachment id must be non-empty and manifest sequence '
        'must not be negative.',
      );
    }
    final material = await _primitives.deriveKey(
      secret: conversationEpochSecret,
      nonce: utf8.encode(conversationEpochId),
      info: utf8.encode(
        'pqc-chat-attachment-v2:$attachmentId:$manifestSequence',
      ),
      length: 48,
    );
    return PqcAttachmentDescriptor(
      cipherVersion: PqcV2Wire.attachmentCipherVersion,
      fileKeyBase64: base64Encode(material.sublist(0, 32)),
      nonceSeedBase64: base64Encode(material.sublist(32)),
      conversationEpochId: conversationEpochId,
      manifestSequence: manifestSequence,
    );
  }

  Future<PqcAttachmentChunk> encryptChunk({
    required List<int> plaintext,
    required PqcAttachmentDescriptor descriptor,
    required int chunkIndex,
  }) async {
    _validateDescriptor(descriptor);
    final box = await _primitives.encryptAead(
      plaintext: plaintext,
      key: base64Decode(descriptor.fileKeyBase64),
      nonce: _deriveNonce(descriptor, chunkIndex),
    );
    return PqcAttachmentChunk(
      ciphertext: [...box.ciphertext, ...box.mac],
      plaintextLength: plaintext.length,
    );
  }

  Future<Uint8List> decryptChunk({
    required List<int> ciphertext,
    required PqcAttachmentDescriptor descriptor,
    required int chunkIndex,
  }) async {
    _validateDescriptor(descriptor);
    if (ciphertext.length < 16) {
      throw const FormatException('Encrypted attachment chunk is too short.');
    }
    final macStart = ciphertext.length - 16;
    return _primitives.decryptAead(
      box: PqcAeadBox(
        nonce: _deriveNonce(descriptor, chunkIndex),
        ciphertext: ciphertext.sublist(0, macStart),
        mac: ciphertext.sublist(macStart),
      ),
      key: base64Decode(descriptor.fileKeyBase64),
    );
  }

  String buildManifestSha256(PqcAttachmentManifest manifest) {
    validateManifest(manifest);
    final bytes = utf8.encode(jsonEncode(manifest.canonicalJson()));
    return _hex(_primitives.sha256(bytes));
  }

  bool verifyManifestSha256(
    PqcAttachmentManifest manifest,
    String expectedSha256,
  ) {
    final actual = buildManifestSha256(manifest);
    return _constantTimeEquals(
      utf8.encode(actual.toLowerCase()),
      utf8.encode(expectedSha256.toLowerCase()),
    );
  }

  void validateManifest(PqcAttachmentManifest manifest) {
    if (manifest.filename.trim().isEmpty ||
        manifest.mimeType.trim().isEmpty ||
        manifest.cipherVersion != PqcV2Wire.attachmentCipherVersion ||
        manifest.chunkSize <= 0 ||
        manifest.plaintextSize < 0 ||
        manifest.ciphertextSize < 0 ||
        manifest.totalChunks < 0 ||
        manifest.recoveryManifestSequence < 0) {
      throw const FormatException('Invalid attachment manifest metadata.');
    }
    final expectedChunks = manifest.plaintextSize == 0
        ? 0
        : (manifest.plaintextSize + manifest.chunkSize - 1) ~/
              manifest.chunkSize;
    final expectedCiphertextSize =
        manifest.plaintextSize + (expectedChunks * 16);
    if (manifest.totalChunks != expectedChunks ||
        manifest.ciphertextSize != expectedCiphertextSize ||
        !_isSha256(manifest.plaintextSha256)) {
      throw const FormatException(
        'Attachment manifest sizes are inconsistent.',
      );
    }
  }

  Uint8List _deriveNonce(PqcAttachmentDescriptor descriptor, int chunkIndex) {
    if (chunkIndex < 0) {
      throw ArgumentError.value(chunkIndex, 'chunkIndex');
    }
    final index = ByteData(8)..setUint64(0, chunkIndex);
    return Uint8List.fromList(
      _primitives
          .sha256([
            ...base64Decode(descriptor.nonceSeedBase64),
            ...index.buffer.asUint8List(),
          ])
          .sublist(0, 12),
    );
  }

  void _validateDescriptor(PqcAttachmentDescriptor descriptor) {
    if (descriptor.cipherVersion != PqcV2Wire.attachmentCipherVersion ||
        base64Decode(descriptor.fileKeyBase64).length != 32 ||
        base64Decode(descriptor.nonceSeedBase64).length != 16 ||
        descriptor.manifestSequence < 0) {
      throw const FormatException('Invalid PQCv2 attachment descriptor.');
    }
  }
}

bool _isSha256(String value) => RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(value);

String _hex(List<int> bytes) =>
    bytes.map((value) => value.toRadixString(16).padLeft(2, '0')).join();

bool _constantTimeEquals(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
