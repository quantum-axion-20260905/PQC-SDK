import 'dart:convert';
import 'dart:typed_data';

import 'crypto_utils.dart';
import 'models.dart';
import 'primitives.dart';

/// Wire representation of a post-quantum ratcheted message.
///
/// Provides Forward Secrecy (FS) and Post-Compromise Security (PCS) using
/// continuous ML-KEM key encapsulation and HKDF-SHA256 symmetric chain ratcheting.
class PqcRatchetEnvelope {
  const PqcRatchetEnvelope({
    required this.protocolVersion,
    required this.conversationId,
    required this.sequenceNumber,
    required this.senderDeviceId,
    required this.ephemeralKemPublicKeyBase64,
    required this.kemCiphertextBase64,
    required this.ciphertextBase64,
    required this.nonceBase64,
    required this.macBase64,
    this.signatureBase64,
  });

  static const currentProtocolVersion = 1;
  static const prefix = 'pqc:ratchet:v1';

  final int protocolVersion;
  final int conversationId;
  final int sequenceNumber;
  final String senderDeviceId;
  final String ephemeralKemPublicKeyBase64;
  final String kemCiphertextBase64;
  final String ciphertextBase64;
  final String nonceBase64;
  final String macBase64;
  final String? signatureBase64;

  Map<String, dynamic> toJson({bool includeSignature = true}) => {
    'protocol_version': protocolVersion,
    'conversation_id': conversationId,
    'sequence_number': sequenceNumber,
    'sender_device_id': senderDeviceId,
    'ephemeral_kem_public_key': ephemeralKemPublicKeyBase64,
    'kem_ciphertext': kemCiphertextBase64,
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

  static PqcRatchetEnvelope decode(String payload) {
    if (!payload.startsWith('$prefix:')) {
      throw const FormatException('Unsupported PQC ratchet payload prefix.');
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
      throw const FormatException('Invalid ratchet payload document.');
    }
    final map = Map<String, dynamic>.from(decoded);
    return PqcRatchetEnvelope(
      protocolVersion: map['protocol_version'] as int? ?? 0,
      conversationId: map['conversation_id'] as int? ?? 0,
      sequenceNumber: map['sequence_number'] as int? ?? -1,
      senderDeviceId: map['sender_device_id'] as String? ?? '',
      ephemeralKemPublicKeyBase64:
          map['ephemeral_kem_public_key'] as String? ?? '',
      kemCiphertextBase64: map['kem_ciphertext'] as String? ?? '',
      ciphertextBase64: map['ciphertext'] as String? ?? '',
      nonceBase64: map['nonce'] as String? ?? '',
      macBase64: map['mac'] as String? ?? '',
      signatureBase64: map['signature'] as String?,
    );
  }
}

class PqcInitiatorHandshake {
  const PqcInitiatorHandshake({
    required this.session,
    required this.initialKemCiphertextBase64,
  });

  final PqcRatchetSession session;
  final String initialKemCiphertextBase64;
}

/// Continuous Post-Quantum Ratchet Session.
///
/// Implements:
/// 1. Forward Secrecy: Each message uses an ephemeral message key derived via HKDF
///    that is erased (zeroized) immediately after encryption/decryption.
/// 2. Post-Compromise Security: Continuous ML-KEM exchange heals the session if a past
///    root key is compromised.
/// 3. Sender Authentication: Each payload is authenticated using ML-DSA-65.
class PqcRatchetSession {
  PqcRatchetSession({
    required this.conversationId,
    required this.localDevice,
    required this.remoteDeviceId,
    required PqcPrimitiveSuite primitives,
    required List<int> initialSharedSecret,
  }) : _primitives = primitives,
       _rootKey = Uint8List.fromList(initialSharedSecret),
       _sendingChainKey = Uint8List(32),
       _receivingChainKey = Uint8List(32) {
    if (conversationId <= 0) {
      throw ArgumentError.value(conversationId, 'conversationId', 'Must be positive.');
    }
  }

  static const int maxSkippedMessages = 100;

  final int conversationId;
  final PqcDeviceKeyset localDevice;
  final String remoteDeviceId;
  final PqcPrimitiveSuite _primitives;

  Uint8List _rootKey;
  Uint8List _sendingChainKey;
  Uint8List _receivingChainKey;
  final Map<int, Uint8List> _skippedChainKeys = {};
  int _sendSequence = 0;
  int _receiveSequence = 0;
  bool _isDisposed = false;

  bool get isDisposed => _isDisposed;
  int get sendSequence => _sendSequence;
  int get receiveSequence => _receiveSequence;

  /// Initiator initialization: sets up initial sending chain key.
  static Future<PqcInitiatorHandshake> createInitiator({
    required int conversationId,
    required PqcDeviceKeyset localDevice,
    required PqcDevicePublicKey remoteDevice,
    required PqcPrimitiveSuite primitives,
  }) async {
    final kem = primitives.encapsulate(remoteDevice.kemPublicKeyBase64);
    try {
      final initialSecret = await primitives.deriveKey(
        secret: kem.sharedSecret,
        nonce: utf8.encode('pqc-ratchet-setup-v1'),
        info: utf8.encode('$conversationId:${localDevice.deviceId}:${remoteDevice.deviceId}'),
      );
      final session = PqcRatchetSession(
        conversationId: conversationId,
        localDevice: localDevice,
        remoteDeviceId: remoteDevice.deviceId,
        primitives: primitives,
        initialSharedSecret: initialSecret,
      );
      session._sendingChainKey = await primitives.deriveKey(
        secret: session._rootKey,
        nonce: utf8.encode('send-chain'),
        info: utf8.encode('chain-v1'),
      );
      session._receivingChainKey = await primitives.deriveKey(
        secret: session._rootKey,
        nonce: utf8.encode('recv-chain'),
        info: utf8.encode('chain-v1'),
      );
      return PqcInitiatorHandshake(
        session: session,
        initialKemCiphertextBase64: kem.ciphertextBase64,
      );
    } finally {
      kem.zeroize();
    }
  }

  /// Responder initialization: decapsulates initial secret and sets receiving chain key.
  static Future<PqcRatchetSession> createResponder({
    required int conversationId,
    required PqcDeviceKeyset localDevice,
    required String remoteDeviceId,
    required String initialKemCiphertextBase64,
    required PqcPrimitiveSuite primitives,
  }) async {
    final sharedSecret = primitives.decapsulate(
      ciphertextBase64: initialKemCiphertextBase64,
      secretKeyBase64: localDevice.kemSecretKeyBase64,
    );
    try {
      final initialSecret = await primitives.deriveKey(
        secret: sharedSecret,
        nonce: utf8.encode('pqc-ratchet-setup-v1'),
        info: utf8.encode('$conversationId:$remoteDeviceId:${localDevice.deviceId}'),
      );
      final session = PqcRatchetSession(
        conversationId: conversationId,
        localDevice: localDevice,
        remoteDeviceId: remoteDeviceId,
        primitives: primitives,
        initialSharedSecret: initialSecret,
      );
      session._receivingChainKey = await primitives.deriveKey(
        secret: session._rootKey,
        nonce: utf8.encode('send-chain'),
        info: utf8.encode('chain-v1'),
      );
      session._sendingChainKey = await primitives.deriveKey(
        secret: session._rootKey,
        nonce: utf8.encode('recv-chain'),
        info: utf8.encode('chain-v1'),
      );
      return session;
    } finally {
      secureZero(sharedSecret);
    }
  }

  /// Encrypts plaintext with forward secrecy and authenticates via ML-DSA.
  Future<String> encrypt({
    required String plaintext,
    required String remoteKemPublicKeyBase64,
  }) async {
    _assertActive();

    // 1. Perform ephemeral ML-KEM step for Post-Compromise Security
    final kem = _primitives.encapsulate(remoteKemPublicKeyBase64);
    Uint8List? messageKey;
    Uint8List? newSendingChainKey;
    Uint8List? newRootKey;

    try {
      // Step root key forward with the fresh KEM entropy
      newRootKey = await _primitives.deriveKey(
        secret: _rootKey,
        nonce: kem.sharedSecret,
        info: utf8.encode('root-ratchet-$_sendSequence'),
      );

      // Derive fresh message key bound to both symmetric chain and KEM entropy
      messageKey = await _primitives.deriveKey(
        secret: _sendingChainKey,
        nonce: kem.sharedSecret,
        info: utf8.encode('pqc-msg-$_sendSequence'),
      );

      newSendingChainKey = await _primitives.deriveKey(
        secret: _sendingChainKey,
        nonce: utf8.encode('advance-chain'),
        info: utf8.encode('chain-step-$_sendSequence'),
      );

      final nonce = _primitives.randomBytes(12);
      final aad = utf8.encode('$conversationId:${localDevice.deviceId}:$_sendSequence');

      final box = await _primitives.encryptAead(
        plaintext: utf8.encode(plaintext),
        key: messageKey,
        nonce: nonce,
        associatedData: aad,
      );

      final envelope = PqcRatchetEnvelope(
        protocolVersion: PqcRatchetEnvelope.currentProtocolVersion,
        conversationId: conversationId,
        sequenceNumber: _sendSequence,
        senderDeviceId: localDevice.deviceId,
        ephemeralKemPublicKeyBase64: localDevice.kemPublicKeyBase64,
        kemCiphertextBase64: kem.ciphertextBase64,
        ciphertextBase64: base64Encode(box.ciphertext),
        nonceBase64: base64Encode(box.nonce),
        macBase64: base64Encode(box.mac),
      );

      final signature = _primitives.sign(
        message: utf8.encode(envelope.unsignedCanonicalJson()),
        secretKeyBase64: localDevice.signingSecretKeyBase64,
      );

      // Advance ratchet state atomically
      secureZero(_rootKey);
      _rootKey = newRootKey;
      secureZero(_sendingChainKey);
      _sendingChainKey = newSendingChainKey;
      _sendSequence++;

      return PqcRatchetEnvelope(
        protocolVersion: envelope.protocolVersion,
        conversationId: envelope.conversationId,
        sequenceNumber: envelope.sequenceNumber,
        senderDeviceId: envelope.senderDeviceId,
        ephemeralKemPublicKeyBase64: envelope.ephemeralKemPublicKeyBase64,
        kemCiphertextBase64: envelope.kemCiphertextBase64,
        ciphertextBase64: envelope.ciphertextBase64,
        nonceBase64: envelope.nonceBase64,
        macBase64: envelope.macBase64,
        signatureBase64: signature,
      ).encode();
    } finally {
      kem.zeroize();
      secureZero(messageKey);
    }
  }

  /// Decrypts a ratcheted payload with forward secrecy, out-of-order handling and authenticity.
  Future<String> decrypt({
    required String payload,
    required Set<String> trustedRemoteSigningKeys,
  }) async {
    _assertActive();

    final envelope = PqcRatchetEnvelope.decode(payload);
    if (envelope.conversationId != conversationId ||
        envelope.senderDeviceId != remoteDeviceId) {
      throw const FormatException('Ratchet envelope conversation/sender mismatch.');
    }

    final signature = envelope.signatureBase64;
    if (signature == null || signature.isEmpty) {
      throw const FormatException('Missing required ML-DSA ratchet signature.');
    }

    // Verify sender signature
    var verified = false;
    for (final trustedKey in trustedRemoteSigningKeys) {
      if (_primitives.verify(
        message: utf8.encode(envelope.unsignedCanonicalJson()),
        signatureBase64: signature,
        publicKeyBase64: trustedKey,
      )) {
        verified = true;
        break;
      }
    }
    if (!verified) {
      throw const FormatException('Ratchet signature verification failed.');
    }

    final seq = envelope.sequenceNumber;
    if (seq < 0) {
      throw const FormatException('Invalid sequence number in ratchet envelope.');
    }

    // Decapsulate ephemeral KEM secret for Post-Compromise Security
    final sharedSecret = _primitives.decapsulate(
      ciphertextBase64: envelope.kemCiphertextBase64,
      secretKeyBase64: localDevice.kemSecretKeyBase64,
    );

    Uint8List? messageKey;
    Uint8List? clear;

    try {
      if (seq < _receiveSequence) {
        // Look up previously skipped message key
        final skippedKey = _skippedChainKeys.remove(seq);
        if (skippedKey == null) {
          throw const FormatException('Replay detected or old sequence number received.');
        }
        try {
          messageKey = await _primitives.deriveKey(
            secret: skippedKey,
            nonce: sharedSecret,
            info: utf8.encode('pqc-msg-$seq'),
          );
        } finally {
          secureZero(skippedKey);
        }
      } else {
        // Check for reasonable skip gap to prevent DoS memory exhaustion
        if (seq - _receiveSequence > maxSkippedMessages) {
          throw FormatException(
            'Too many skipped messages in ratchet sequence: gap is ${seq - _receiveSequence}.',
          );
        }

        // Cache any skipped chain keys between _receiveSequence and seq
        while (_receiveSequence < seq) {
          _skippedChainKeys[_receiveSequence] = Uint8List.fromList(_receivingChainKey);
          final nextChain = await _primitives.deriveKey(
            secret: _receivingChainKey,
            nonce: utf8.encode('advance-chain'),
            info: utf8.encode('chain-step-$_receiveSequence'),
          );
          secureZero(_receivingChainKey);
          _receivingChainKey = nextChain;
          _receiveSequence++;
        }

        messageKey = await _primitives.deriveKey(
          secret: _receivingChainKey,
          nonce: sharedSecret,
          info: utf8.encode('pqc-msg-$seq'),
        );

        final nextChain = await _primitives.deriveKey(
          secret: _receivingChainKey,
          nonce: utf8.encode('advance-chain'),
          info: utf8.encode('chain-step-$seq'),
        );
        secureZero(_receivingChainKey);
        _receivingChainKey = nextChain;
        _receiveSequence = seq + 1;
      }

      final aad = utf8.encode('$conversationId:$remoteDeviceId:$seq');

      clear = await _primitives.decryptAead(
        box: PqcAeadBox(
          nonce: base64Decode(envelope.nonceBase64),
          ciphertext: base64Decode(envelope.ciphertextBase64),
          mac: base64Decode(envelope.macBase64),
        ),
        key: messageKey,
        associatedData: aad,
      );

      return utf8.decode(clear, allowMalformed: false);
    } finally {
      secureZero(sharedSecret);
      secureZero(messageKey);
      secureZero(clear);
    }
  }

  /// Destroys all sensitive key material in memory.
  void dispose() {
    if (_isDisposed) return;
    secureZero(_rootKey);
    secureZero(_sendingChainKey);
    secureZero(_receivingChainKey);
    for (final key in _skippedChainKeys.values) {
      secureZero(key);
    }
    _skippedChainKeys.clear();
    _isDisposed = true;
  }

  void _assertActive() {
    if (_isDisposed) {
      throw StateError('Cannot operate on a disposed PqcRatchetSession.');
    }
  }
}
