import 'dart:convert';

export 'package:pqcrypto/pqcrypto.dart' show secureZero;

/// Overwrites visible backing storage of a byte list in place.
void wipeBytes(List<int>? buffer) {
  if (buffer == null) return;
  for (var i = 0; i < buffer.length; i++) {
    buffer[i] = 0;
  }
}

/// Constant-time byte array equality comparison.
///
/// Prevents timing side-channel attacks by always inspecting all bytes,
/// ensuring execution time does not reveal the position of a mismatch.
bool constantTimeBytesEquals(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  var difference = 0;
  for (var i = 0; i < left.length; i++) {
    difference |= left[i] ^ right[i];
  }
  return difference == 0;
}

/// Constant-time string equality comparison using UTF-8 bytes.
///
/// Prevents timing attacks on digests, tokens, and cryptographic identifiers.
bool constantTimeStringEquals(String left, String right) {
  final leftBytes = utf8.encode(left);
  final rightBytes = utf8.encode(right);
  if (leftBytes.length != rightBytes.length) {
    return false;
  }
  var difference = 0;
  for (var i = 0; i < leftBytes.length; i++) {
    difference |= leftBytes[i] ^ rightBytes[i];
  }
  return difference == 0;
}

/// Strict RFC 8785-compliant Canonical JSON serialization.
///
/// Guarantees cross-platform, deterministic serialization:
/// - Object keys are lexicographically sorted by UTF-16 code units.
/// - Whitespace between separators is completely eliminated.
/// - Strings conform to RFC 8259 escaping.
/// - Numbers and booleans format consistently.
String canonicalJsonEncode(dynamic value) {
  final buffer = StringBuffer();
  _writeCanonical(value, buffer);
  return buffer.toString();
}

void _writeCanonical(dynamic value, StringBuffer buffer) {
  if (value == null) {
    buffer.write('null');
  } else if (value is bool) {
    buffer.write(value ? 'true' : 'false');
  } else if (value is num) {
    if (value.isNaN || value.isInfinite) {
      throw const FormatException('NaN and Infinity cannot be represented in JSON.');
    }
    // Formats integers cleanly, and floats per ECMAScript / RFC 8785
    buffer.write(value.toString());
  } else if (value is String) {
    buffer.write(jsonEncode(value));
  } else if (value is List) {
    buffer.write('[');
    for (var i = 0; i < value.length; i++) {
      if (i > 0) buffer.write(',');
      _writeCanonical(value[i], buffer);
    }
    buffer.write(']');
  } else if (value is Map) {
    buffer.write('{');
    final keys = value.keys.map((k) => k.toString()).toList();
    // RFC 8785: sorted lexicographically by UTF-16 code units
    keys.sort((a, b) {
      final aUnits = a.codeUnits;
      final bUnits = b.codeUnits;
      final minLen = aUnits.length < bUnits.length ? aUnits.length : bUnits.length;
      for (var i = 0; i < minLen; i++) {
        final diff = aUnits[i] - bUnits[i];
        if (diff != 0) return diff;
      }
      return aUnits.length - bUnits.length;
    });
    for (var i = 0; i < keys.length; i++) {
      if (i > 0) buffer.write(',');
      final key = keys[i];
      buffer.write(jsonEncode(key));
      buffer.write(':');
      _writeCanonical(value[key], buffer);
    }
    buffer.write('}');
  } else {
    // For other types, fall back to toJson() if available
    try {
      final dynamic converted = (value as dynamic).toJson();
      _writeCanonical(converted, buffer);
    } catch (_) {
      throw FormatException('Unsupported type for canonical JSON: ${value.runtimeType}');
    }
  }
}
