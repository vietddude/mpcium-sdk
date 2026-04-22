import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';

class MpciumSdk {
  static const MethodChannel _methods = MethodChannel('mpcium_sdk');
  static const EventChannel _events = EventChannel('mpcium_sdk/events');

  static Stream<List<MpciumEvent>> get events {
    return _events.receiveBroadcastStream().map((dynamic value) {
      return MpciumEvent.decodeBatch(value as String);
    });
  }

  static Future<MpciumIdentity> initialize({String? configJson}) async {
    final raw = await _methods.invokeMethod<Map<dynamic, dynamic>>(
      'initialize',
      <String, Object?>{'configJson': configJson},
    );
    if (raw == null) {
      throw StateError('Native initialize returned no identity data');
    }
    return MpciumIdentity.fromMap(raw);
  }

  static Future<void> start() {
    return _methods.invokeMethod<void>('start');
  }

  static Future<void> stop() {
    return _methods.invokeMethod<void>('stop');
  }

  static Future<void> approveSign(
    String sessionId, {
    required bool approved,
    String reason = '',
  }) {
    return _methods.invokeMethod<void>('approveSign', <String, Object?>{
      'sessionId': sessionId,
      'approved': approved,
      'reason': reason,
    });
  }

  static Future<String> getParticipantId() async {
    return await _methods.invokeMethod<String>('getParticipantId') ?? '';
  }

  static Future<String> getIdentityPublicKeyBase64() async {
    return await _methods.invokeMethod<String>('getIdentityPublicKeyBase64') ??
        '';
  }
}

class MpciumIdentity {
  const MpciumIdentity({
    required this.participantId,
    required this.identityPublicKeyBase64,
    required this.identityPublicKeyHex,
    required this.configJson,
  });

  factory MpciumIdentity.fromMap(Map<dynamic, dynamic> value) {
    return MpciumIdentity(
      participantId: value['participantId'] as String? ?? '',
      identityPublicKeyBase64:
          value['identityPublicKeyBase64'] as String? ?? '',
      identityPublicKeyHex: value['identityPublicKeyHex'] as String? ?? '',
      configJson: value['configJson'] as String? ?? '',
    );
  }

  final String participantId;
  final String identityPublicKeyBase64;
  final String identityPublicKeyHex;
  final String configJson;
}

class MpciumEvent {
  const MpciumEvent({
    required this.type,
    required this.data,
  });

  factory MpciumEvent.fromJson(Map<String, dynamic> value) {
    return MpciumEvent(
      type: value['type'] as String? ?? '',
      data: value,
    );
  }

  static List<MpciumEvent> decodeBatch(String jsonValue) {
    final decoded = jsonDecode(jsonValue);
    if (decoded is! List) {
      throw const FormatException('Expected an event array');
    }
    return decoded
        .whereType<Map>()
        .map((value) => MpciumEvent.fromJson(Map<String, dynamic>.from(value)))
        .toList(growable: false);
  }

  final String type;
  final Map<String, dynamic> data;

  String get sessionId => data['session_id'] as String? ?? '';
  String get message => data['message'] as String? ?? '';
}
