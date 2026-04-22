import 'dart:convert';

class Participant {
  Participant({
    this.id = '',
    this.identityPublicKeyHex = '',
  });

  factory Participant.fromBuffer(List<int> bytes) {
    final reader = _ProtoReader(bytes);
    final value = Participant();
    while (!reader.isDone) {
      final tag = reader.readVarint();
      switch (tag >> 3) {
        case 1:
          value.id = reader.readString();
          break;
        case 2:
          value.identityPublicKeyHex = reader.readString();
          break;
        default:
          reader.skip(tag & 7);
          break;
      }
    }
    return value;
  }

  String id;
  String identityPublicKeyHex;

  List<int> writeToBuffer() {
    final writer = _ProtoWriter();
    writer.writeString(1, id);
    writer.writeString(2, identityPublicKeyHex);
    return writer.takeBytes();
  }
}

class KeygenRequest {
  KeygenRequest({
    this.protocol = '',
    this.threshold = 0,
    this.walletId = '',
    List<Participant>? participants,
  }) : participants = participants ?? <Participant>[];

  String protocol;
  int threshold;
  String walletId;
  final List<Participant> participants;

  List<int> writeToBuffer() {
    final writer = _ProtoWriter();
    writer.writeString(1, protocol);
    writer.writeVarintField(2, threshold);
    writer.writeString(3, walletId);
    for (final participant in participants) {
      writer.writeMessage(4, participant.writeToBuffer());
    }
    return writer.takeBytes();
  }
}

class SignRequest {
  SignRequest({
    this.protocol = '',
    this.threshold = 0,
    this.walletId = '',
    this.signingInputHex = '',
    List<Participant>? participants,
    List<int>? derivationPath,
    this.derivationDeltaHex = '',
  })  : participants = participants ?? <Participant>[],
        derivationPath = derivationPath ?? <int>[];

  String protocol;
  int threshold;
  String walletId;
  String signingInputHex;
  final List<Participant> participants;
  final List<int> derivationPath;
  String derivationDeltaHex;

  List<int> writeToBuffer() {
    final writer = _ProtoWriter();
    writer.writeString(1, protocol);
    writer.writeVarintField(2, threshold);
    writer.writeString(3, walletId);
    writer.writeString(4, signingInputHex);
    for (final participant in participants) {
      writer.writeMessage(5, participant.writeToBuffer());
    }
    writer.writePackedVarints(6, derivationPath);
    writer.writeString(7, derivationDeltaHex);
    return writer.takeBytes();
  }
}

class SessionLookup {
  SessionLookup({this.sessionId = ''});

  String sessionId;

  List<int> writeToBuffer() {
    final writer = _ProtoWriter();
    writer.writeString(1, sessionId);
    return writer.takeBytes();
  }
}

class RequestAccepted {
  RequestAccepted({
    this.accepted = false,
    this.sessionId = '',
    this.expiresAt = '',
    this.errorCode = '',
    this.errorMessage = '',
  });

  factory RequestAccepted.fromBuffer(List<int> bytes) {
    final reader = _ProtoReader(bytes);
    final value = RequestAccepted();
    while (!reader.isDone) {
      final tag = reader.readVarint();
      switch (tag >> 3) {
        case 1:
          value.accepted = reader.readVarint() != 0;
          break;
        case 2:
          value.sessionId = reader.readString();
          break;
        case 3:
          value.expiresAt = reader.readString();
          break;
        case 4:
          value.errorCode = reader.readString();
          break;
        case 5:
          value.errorMessage = reader.readString();
          break;
        default:
          reader.skip(tag & 7);
          break;
      }
    }
    return value;
  }

  bool accepted;
  String sessionId;
  String expiresAt;
  String errorCode;
  String errorMessage;
}

class SessionResult {
  SessionResult({
    this.completed = false,
    this.sessionId = '',
    this.keyId = '',
    this.publicKeyHex = '',
    this.signatureHex = '',
    this.signatureRecoveryHex = '',
    this.rHex = '',
    this.sHex = '',
    this.signedInputHex = '',
    this.errorCode = '',
    this.errorMessage = '',
    this.ecdsaPubkey = '',
    this.eddsaPubkey = '',
  });

  factory SessionResult.fromBuffer(List<int> bytes) {
    final reader = _ProtoReader(bytes);
    final value = SessionResult();
    while (!reader.isDone) {
      final tag = reader.readVarint();
      switch (tag >> 3) {
        case 1:
          value.completed = reader.readVarint() != 0;
          break;
        case 2:
          value.sessionId = reader.readString();
          break;
        case 3:
          value.keyId = reader.readString();
          break;
        case 4:
          value.publicKeyHex = reader.readString();
          break;
        case 5:
          value.signatureHex = reader.readString();
          break;
        case 6:
          value.signatureRecoveryHex = reader.readString();
          break;
        case 7:
          value.rHex = reader.readString();
          break;
        case 8:
          value.sHex = reader.readString();
          break;
        case 9:
          value.signedInputHex = reader.readString();
          break;
        case 10:
          value.errorCode = reader.readString();
          break;
        case 11:
          value.errorMessage = reader.readString();
          break;
        case 12:
          value.ecdsaPubkey = reader.readString();
          break;
        case 13:
          value.eddsaPubkey = reader.readString();
          break;
        default:
          reader.skip(tag & 7);
          break;
      }
    }
    return value;
  }

  bool completed;
  String sessionId;
  String keyId;
  String publicKeyHex;
  String signatureHex;
  String signatureRecoveryHex;
  String rHex;
  String sHex;
  String signedInputHex;
  String errorCode;
  String errorMessage;
  String ecdsaPubkey;
  String eddsaPubkey;
}

class _ProtoWriter {
  final List<int> _bytes = <int>[];

  List<int> takeBytes() => List<int>.unmodifiable(_bytes);

  void writeString(int field, String value) {
    if (value.isEmpty) return;
    final payload = utf8.encode(value);
    _writeTag(field, 2);
    _writeVarint(payload.length);
    _bytes.addAll(payload);
  }

  void writeMessage(int field, List<int> payload) {
    _writeTag(field, 2);
    _writeVarint(payload.length);
    _bytes.addAll(payload);
  }

  void writeVarintField(int field, int value) {
    if (value == 0) return;
    _writeTag(field, 0);
    _writeVarint(value);
  }

  void writePackedVarints(int field, List<int> values) {
    if (values.isEmpty) return;
    final nested = _ProtoWriter();
    for (final value in values) {
      nested._writeVarint(value);
    }
    writeMessage(field, nested.takeBytes());
  }

  void _writeTag(int field, int wireType) {
    _writeVarint((field << 3) | wireType);
  }

  void _writeVarint(int value) {
    var current = value;
    while (current >= 0x80) {
      _bytes.add((current & 0x7f) | 0x80);
      current >>= 7;
    }
    _bytes.add(current);
  }
}

class _ProtoReader {
  _ProtoReader(List<int> bytes) : _bytes = bytes;

  final List<int> _bytes;
  int _offset = 0;

  bool get isDone => _offset >= _bytes.length;

  int readVarint() {
    var shift = 0;
    var result = 0;
    while (_offset < _bytes.length) {
      final byte = _bytes[_offset++];
      result |= (byte & 0x7f) << shift;
      if ((byte & 0x80) == 0) return result;
      shift += 7;
    }
    throw const FormatException('truncated varint');
  }

  String readString() {
    final length = readVarint();
    if (_offset + length > _bytes.length) {
      throw const FormatException('truncated string');
    }
    final value = utf8.decode(_bytes.sublist(_offset, _offset + length));
    _offset += length;
    return value;
  }

  void skip(int wireType) {
    switch (wireType) {
      case 0:
        readVarint();
        break;
      case 1:
        _offset += 8;
        break;
      case 2:
        final length = readVarint();
        _offset += length;
        break;
      case 5:
        _offset += 4;
        break;
      default:
        throw FormatException('unsupported wire type $wireType');
    }
    if (_offset > _bytes.length) {
      throw const FormatException('truncated field');
    }
  }
}
