import 'dart:convert';
import 'dart:typed_data';

import 'crypto_utils.dart';
import 'models.dart';
import 'primitives.dart';
import 'v3_envelope.dart';

/// One-time or rekey distribution envelope for a participant's Sender Key.
///
/// Sent to group members once when joining or after membership changes,
/// carrying the initial chain key wrapped per member device with ML-KEM.
class PqcSenderKeyDistribution {
  const PqcSenderKeyDistribution({
    required this.conversationId,
    required this.senderDeviceId,
    required this.senderKeysetId,
    required this.epochId,
    required this.signingPublicKey,
    required this.wraps,
    this.signature,
  });

  static const prefix = 'pqc:group-sender-key:v1';

  final int conversationId;
  final String senderDeviceId;
  final String senderKeysetId;
  final String epochId;
  final String signingPublicKey;
  final List<PqcV3RecipientWrap> wraps;
  final String? signature;

  Map<String, dynamic> toJson({bool includeSignature = true}) => {
    'prefix': prefix,
    'conversation_id': conversationId,
    'sender_device_id': senderDeviceId,
    'sender_keyset_id': senderKeysetId,
    'epoch_id': epochId,
    'signing_public_key': signingPublicKey,
    'wraps': wraps.map((w) => w.toJson()).toList(),
    if (includeSignature && signature != null) 'signature': signature,
  };

  String unsignedCanonicalJson() => canonicalJsonEncode(
    toJson(includeSignature: false),
  );

  String encode() =>
      '$prefix:${base64UrlEncode(utf8.encode(canonicalJsonEncode(toJson())))}';

  static PqcSenderKeyDistribution decode(String payload) {
    if (!payload.startsWith('$prefix:')) {
      throw const FormatException('Unsupported sender key distribution prefix.');
    }
    final encoded = payload.substring(prefix.length + 1);
    final padded = encoded.padRight(
      encoded.length + ((4 - encoded.length % 4) % 4),
      '=',
    );
    final decoded = jsonDecode(
      utf8.decode(base64Url.decode(padded), allowMalformed: false),
    );
    if (decoded is! Map) {
      throw const FormatException('Invalid sender key distribution document.');
    }
    final map = Map<String, dynamic>.from(decoded);
    final wrapsList = map['wraps'];
    if (wrapsList is! List) {
      throw const FormatException('Sender key wraps must be a list.');
    }
    return PqcSenderKeyDistribution(
      conversationId: map['conversation_id'] as int? ?? 0,
      senderDeviceId: map['sender_device_id'] as String? ?? '',
      senderKeysetId: map['sender_keyset_id'] as String? ?? '',
      epochId: map['epoch_id'] as String? ?? '',
      signingPublicKey: map['signing_public_key'] as String? ?? '',
      wraps: wrapsList
          .map((item) => PqcV3RecipientWrap.fromJson(Map<String, dynamic>.from(item as Map)))
          .toList(growable: false),
      signature: map['signature'] as String?,
    );
  }
}

/// Constant O(1) size group message encrypted with the sender's current ratchet key.
///
/// Regardless of group size (10 or 10,000 members), the ciphertext size remains
/// constant (~300 bytes + plaintext size).
class PqcGroupSenderMessage {
  const PqcGroupSenderMessage({
    required this.conversationId,
    required this.epochId,
    required this.sequenceNumber,
    required this.senderDeviceId,
    required this.ciphertextBase64,
    required this.nonceBase64,
    required this.macBase64,
    this.signatureBase64,
  });

  static const prefix = 'pqc:group-msg:v1';

  final int conversationId;
  final String epochId;
  final int sequenceNumber;
  final String senderDeviceId;
  final String ciphertextBase64;
  final String nonceBase64;
  final String macBase64;
  final String? signatureBase64;

  Map<String, dynamic> toJson({bool includeSignature = true}) => {
    'prefix': prefix,
    'conversation_id': conversationId,
    'epoch_id': epochId,
    'sequence_number': sequenceNumber,
    'sender_device_id': senderDeviceId,
    'ciphertext': ciphertextBase64,
    'nonce': nonceBase64,
    'mac': macBase64,
    if (includeSignature && signatureBase64 != null)
      'signature': signatureBase64,
  };

  String unsignedCanonicalJson() => canonicalJsonEncode(
    toJson(includeSignature: false),
  );

  String encode() =>
      '$prefix:${base64UrlEncode(utf8.encode(canonicalJsonEncode(toJson())))}';

  static PqcGroupSenderMessage decode(String payload) {
    if (!payload.startsWith('$prefix:')) {
      throw const FormatException('Unsupported group sender message prefix.');
    }
    final encoded = payload.substring(prefix.length + 1);
    final padded = encoded.padRight(
      encoded.length + ((4 - encoded.length % 4) % 4),
      '=',
    );
    final decoded = jsonDecode(
      utf8.decode(base64Url.decode(padded), allowMalformed: false),
    );
    if (decoded is! Map) {
      throw const FormatException('Invalid group sender message document.');
    }
    final map = Map<String, dynamic>.from(decoded);
    return PqcGroupSenderMessage(
      conversationId: map['conversation_id'] as int? ?? 0,
      epochId: map['epoch_id'] as String? ?? '',
      sequenceNumber: map['sequence_number'] as int? ?? -1,
      senderDeviceId: map['sender_device_id'] as String? ?? '',
      ciphertextBase64: map['ciphertext'] as String? ?? '',
      nonceBase64: map['nonce'] as String? ?? '',
      macBase64: map['mac'] as String? ?? '',
      signatureBase64: map['signature'] as String?,
    );
  }
}

/// Scalable Post-Quantum Group Messaging Engine.
///
/// Implements the Sender-Key model with ML-KEM distribution and continuous
/// HKDF symmetric ratcheting for forward secrecy in groups.
class PqcGroupSenderKeyEngine {
  PqcGroupSenderKeyEngine(this._primitives);

  final PqcPrimitiveSuite _primitives;

  /// Generates a new sender key distribution envelope for a group epoch.
  Future<({PqcSenderKeyDistribution distribution, Uint8List senderChainKey})>
      createDistribution({
    required int conversationId,
    required String epochId,
    required PqcDeviceKeyset sender,
    required Iterable<PqcDevicePublicKey> memberDevices,
  }) async {
    final chainKey = _primitives.randomBytes(32);
    final wraps = <PqcV3RecipientWrap>[];

    for (final member in memberDevices) {
      final kem = _primitives.encapsulate(member.kemPublicKeyBase64);
      try {
        final box = await _primitives.encryptAead(
          plaintext: chainKey,
          key: kem.sharedSecret,
          nonce: _primitives.randomBytes(12),
          associatedData: utf8.encode('$conversationId:$epochId:${member.deviceId}'),
        );
        wraps.add(
          PqcV3RecipientWrap(
            deviceId: member.deviceId,
            keysetId: member.keysetId,
            kemCiphertext: kem.ciphertextBase64,
            wrappedKey: base64Encode([...box.nonce, ...box.ciphertext, ...box.mac]),
          ),
        );
      } finally {
        kem.zeroize();
      }
    }

    final unsigned = PqcSenderKeyDistribution(
      conversationId: conversationId,
      senderDeviceId: sender.deviceId,
      senderKeysetId: sender.keysetId,
      epochId: epochId,
      signingPublicKey: sender.signingPublicKeyBase64,
      wraps: wraps,
    );

    final signature = _primitives.sign(
      message: utf8.encode(unsigned.unsignedCanonicalJson()),
      secretKeyBase64: sender.signingSecretKeyBase64,
    );

    final distribution = PqcSenderKeyDistribution(
      conversationId: unsigned.conversationId,
      senderDeviceId: unsigned.senderDeviceId,
      senderKeysetId: unsigned.senderKeysetId,
      epochId: unsigned.epochId,
      signingPublicKey: unsigned.signingPublicKey,
      wraps: unsigned.wraps,
      signature: signature,
    );

    return (distribution: distribution, senderChainKey: chainKey);
  }

  /// Encrypts an O(1) group message using the local active sender chain key.
  Future<({String payload, Uint8List nextChainKey})> encryptGroupMessage({
    required int conversationId,
    required String epochId,
    required int sequenceNumber,
    required String plaintext,
    required PqcDeviceKeyset sender,
    required List<int> currentChainKey,
  }) async {
    final messageKey = await _primitives.deriveKey(
      secret: currentChainKey,
      nonce: utf8.encode('msg-key-$sequenceNumber'),
      info: utf8.encode('pqc-grp-msg-v1'),
    );

    final nextChainKey = await _primitives.deriveKey(
      secret: currentChainKey,
      nonce: utf8.encode('advance-chain'),
      info: utf8.encode('grp-step-$sequenceNumber'),
    );

    Uint8List? nonce;
    try {
      nonce = _primitives.randomBytes(12);
      final aad = utf8.encode('$conversationId:$epochId:${sender.deviceId}:$sequenceNumber');

      final box = await _primitives.encryptAead(
        plaintext: utf8.encode(plaintext),
        key: messageKey,
        nonce: nonce,
        associatedData: aad,
      );

      final envelope = PqcGroupSenderMessage(
        conversationId: conversationId,
        epochId: epochId,
        sequenceNumber: sequenceNumber,
        senderDeviceId: sender.deviceId,
        ciphertextBase64: base64Encode(box.ciphertext),
        nonceBase64: base64Encode(box.nonce),
        macBase64: base64Encode(box.mac),
      );

      final signature = _primitives.sign(
        message: utf8.encode(envelope.unsignedCanonicalJson()),
        secretKeyBase64: sender.signingSecretKeyBase64,
      );

      final signedEnvelope = PqcGroupSenderMessage(
        conversationId: envelope.conversationId,
        epochId: envelope.epochId,
        sequenceNumber: envelope.sequenceNumber,
        senderDeviceId: envelope.senderDeviceId,
        ciphertextBase64: envelope.ciphertextBase64,
        nonceBase64: envelope.nonceBase64,
        macBase64: envelope.macBase64,
        signatureBase64: signature,
      );

      return (payload: signedEnvelope.encode(), nextChainKey: nextChainKey);
    } finally {
      secureZero(messageKey);
    }
  }

  /// Resolves the sender's initial chain key from a distribution envelope.
  Future<Uint8List> receiveDistribution({
    required PqcSenderKeyDistribution distribution,
    required Iterable<PqcDeviceKeyset> localKeysets,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    final trusted = trustedSigningKeysByDevice[distribution.senderDeviceId];
    if (trusted == null || !trusted.contains(distribution.signingPublicKey)) {
      throw const FormatException('Sender key distribution from untrusted sender.');
    }
    if (distribution.signature == null ||
        !_primitives.verify(
          message: utf8.encode(distribution.unsignedCanonicalJson()),
          signatureBase64: distribution.signature!,
          publicKeyBase64: distribution.signingPublicKey,
        )) {
      throw const FormatException('Distribution signature verification failed.');
    }

    PqcDeviceKeyset? selectedKeyset;
    PqcV3RecipientWrap? selectedWrap;
    for (final keyset in localKeysets) {
      for (final wrap in distribution.wraps) {
        if (wrap.deviceId == keyset.deviceId && wrap.keysetId == keyset.keysetId) {
          selectedKeyset = keyset;
          selectedWrap = wrap;
          break;
        }
      }
      if (selectedWrap != null) break;
    }

    if (selectedKeyset == null || selectedWrap == null) {
      throw const FormatException('No local keyset match for sender key distribution.');
    }

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
        associatedData: utf8.encode(
          '${distribution.conversationId}:${distribution.epochId}:${selectedKeyset.deviceId}',
        ),
      );
    } finally {
      secureZero(sharedSecret);
    }
  }

  /// Decrypts an O(1) group message using the sender's active receiving chain key.
  Future<({String plaintext, Uint8List nextChainKey})> decryptGroupMessage({
    required String payload,
    required List<int> currentChainKey,
    required Set<String> trustedSenderSigningKeys,
  }) async {
    final msg = PqcGroupSenderMessage.decode(payload);
    if (msg.signatureBase64 == null) {
      throw const FormatException('Missing group message signature.');
    }

    var signatureValid = false;
    for (final key in trustedSenderSigningKeys) {
      if (_primitives.verify(
        message: utf8.encode(msg.unsignedCanonicalJson()),
        signatureBase64: msg.signatureBase64!,
        publicKeyBase64: key,
      )) {
        signatureValid = true;
        break;
      }
    }
    if (!signatureValid) {
      throw const FormatException('Group message signature failed verification.');
    }

    final messageKey = await _primitives.deriveKey(
      secret: currentChainKey,
      nonce: utf8.encode('msg-key-${msg.sequenceNumber}'),
      info: utf8.encode('pqc-grp-msg-v1'),
    );

    final nextChainKey = await _primitives.deriveKey(
      secret: currentChainKey,
      nonce: utf8.encode('advance-chain'),
      info: utf8.encode('grp-step-${msg.sequenceNumber}'),
    );

    Uint8List? clear;
    try {
      final aad = utf8.encode(
        '${msg.conversationId}:${msg.epochId}:${msg.senderDeviceId}:${msg.sequenceNumber}',
      );
      clear = await _primitives.decryptAead(
        box: PqcAeadBox(
          nonce: base64Decode(msg.nonceBase64),
          ciphertext: base64Decode(msg.ciphertextBase64),
          mac: base64Decode(msg.macBase64),
        ),
        key: messageKey,
        associatedData: aad,
      );

      return (
        plaintext: utf8.decode(clear, allowMalformed: false),
        nextChainKey: nextChainKey,
      );
    } finally {
      secureZero(messageKey);
      secureZero(clear);
    }
  }
}
