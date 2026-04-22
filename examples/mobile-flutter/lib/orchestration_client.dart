import 'package:grpc/grpc.dart';

import 'generated/coordinator_orchestration.pb.dart' as pb;
import 'generated/coordinator_orchestration.pbgrpc.dart';

class OrchestrationClient {
  OrchestrationClient({
    required String endpoint,
    Duration timeout = const Duration(minutes: 10),
  })  : _endpoint = endpoint,
        _timeout = timeout;

  final String _endpoint;
  final Duration _timeout;
  static const int _maxWaitAttempts = 3;

  Future<SessionResultView> keygen(KeygenInput input) async {
    final channel = _channel();
    late final pb.RequestAccepted accepted;
    try {
      final client = CoordinatorOrchestrationClient(channel);
      accepted = await client.keygen(
        pb.KeygenRequest(
          protocol: input.protocol.trim(),
          threshold: input.threshold,
          walletId: input.walletId,
          participants: input.participants.map(_toProtoParticipant).toList(),
        ),
        options: CallOptions(timeout: _timeout),
      );
    } finally {
      await channel.shutdown();
    }
    return _waitForResult(accepted);
  }

  Future<SessionResultView> sign(SignInput input) async {
    final channel = _channel();
    late final pb.RequestAccepted accepted;
    try {
      final client = CoordinatorOrchestrationClient(channel);
      accepted = await client.sign(
        pb.SignRequest(
          protocol: input.protocol,
          threshold: input.threshold,
          walletId: input.walletId,
          signingInputHex: input.signingInputHex,
          participants: input.participants.map(_toProtoParticipant).toList(),
          derivationPath: input.derivationPath,
          derivationDeltaHex: input.derivationDeltaHex,
        ),
        options: CallOptions(timeout: _timeout),
      );
    } finally {
      await channel.shutdown();
    }
    return _waitForResult(accepted);
  }

  Future<SessionResultView> _waitForResult(pb.RequestAccepted accepted) async {
    final acceptedView = SessionResultView.fromAccepted(accepted);
    if (!accepted.accepted || accepted.sessionId.isEmpty) {
      return acceptedView;
    }

    for (var attempt = 1; attempt <= _maxWaitAttempts; attempt++) {
      final channel = _channel();
      try {
        final client = CoordinatorOrchestrationClient(channel);
        final result = await client.waitSessionResult(
          pb.SessionLookup(sessionId: accepted.sessionId),
          options: CallOptions(timeout: _timeout),
        );
        return SessionResultView.fromProto(result, accepted: acceptedView);
      } on GrpcError catch (error) {
        if (!_shouldRetryWait(error) || attempt == _maxWaitAttempts) {
          rethrow;
        }
        await Future<void>.delayed(Duration(milliseconds: 400 * attempt));
      } finally {
        await channel.shutdown();
      }
    }

    return acceptedView;
  }

  bool _shouldRetryWait(GrpcError error) {
    final message = error.message ?? '';
    return error.code == StatusCode.unavailable &&
        message.toLowerCase().contains('shutting down');
  }

  ClientChannel _channel() {
    final parsed = GrpcEndpoint.parse(_endpoint);
    return ClientChannel(
      parsed.host,
      port: parsed.port,
      options: const ChannelOptions(
        credentials: ChannelCredentials.insecure(),
      ),
    );
  }

  pb.Participant _toProtoParticipant(ParticipantInput participant) {
    return pb.Participant(
      id: participant.id,
      identityPublicKeyHex: participant.identityPublicKeyHex,
    );
  }
}

class GrpcEndpoint {
  const GrpcEndpoint({
    required this.host,
    required this.port,
  });

  factory GrpcEndpoint.parse(String value) {
    final clean = value.trim().replaceFirst(RegExp(r'^https?://'), '');
    final parts = clean.split(':');
    if (parts.length != 2 || parts[0].isEmpty) {
      throw FormatException('gRPC endpoint must be host:port, got "$value"');
    }
    final port = int.tryParse(parts[1]);
    if (port == null || port <= 0 || port > 65535) {
      throw FormatException('invalid gRPC port in "$value"');
    }
    return GrpcEndpoint(host: parts[0], port: port);
  }

  final String host;
  final int port;
}

class ParticipantInput {
  const ParticipantInput({
    required this.id,
    required this.identityPublicKeyHex,
  });

  final String id;
  final String identityPublicKeyHex;
}

class KeygenInput {
  const KeygenInput({
    required this.threshold,
    required this.walletId,
    required this.participants,
    this.protocol = '',
  });

  final String protocol;
  final int threshold;
  final String walletId;
  final List<ParticipantInput> participants;
}

class SignInput {
  const SignInput({
    required this.protocol,
    required this.threshold,
    required this.walletId,
    required this.signingInputHex,
    required this.participants,
    this.derivationPath = const <int>[],
    this.derivationDeltaHex = '',
  });

  final String protocol;
  final int threshold;
  final String walletId;
  final String signingInputHex;
  final List<ParticipantInput> participants;
  final List<int> derivationPath;
  final String derivationDeltaHex;
}

class SessionResultView {
  const SessionResultView({
    required this.accepted,
    required this.sessionId,
    required this.keyId,
    required this.publicKeyHex,
    required this.ecdsaPubkey,
    required this.eddsaPubkey,
    required this.signatureHex,
    required this.signatureRecoveryHex,
    required this.rHex,
    required this.sHex,
    required this.signedInputHex,
    required this.expiresAt,
    required this.error,
  });

  factory SessionResultView.fromAccepted(pb.RequestAccepted accepted) {
    return SessionResultView(
      accepted: accepted.accepted,
      sessionId: accepted.sessionId,
      keyId: '',
      publicKeyHex: '',
      ecdsaPubkey: '',
      eddsaPubkey: '',
      signatureHex: '',
      signatureRecoveryHex: '',
      rHex: '',
      sHex: '',
      signedInputHex: '',
      expiresAt: accepted.expiresAt,
      error: _joinError(accepted.errorCode, accepted.errorMessage),
    );
  }

  factory SessionResultView.failure(Object error) {
    return SessionResultView(
      accepted: false,
      sessionId: '',
      keyId: '',
      publicKeyHex: '',
      ecdsaPubkey: '',
      eddsaPubkey: '',
      signatureHex: '',
      signatureRecoveryHex: '',
      rHex: '',
      sHex: '',
      signedInputHex: '',
      expiresAt: '',
      error: error.toString(),
    );
  }

  factory SessionResultView.fromProto(
    pb.SessionResult result, {
    required SessionResultView accepted,
  }) {
    final hasTerminalResult = result.publicKeyHex.isNotEmpty ||
        result.ecdsaPubkey.isNotEmpty ||
        result.eddsaPubkey.isNotEmpty ||
        result.signatureHex.isNotEmpty ||
        result.rHex.isNotEmpty ||
        result.signedInputHex.isNotEmpty;
    return SessionResultView(
      accepted: accepted.accepted || result.completed || hasTerminalResult,
      sessionId:
          result.sessionId.isEmpty ? accepted.sessionId : result.sessionId,
      keyId: result.keyId,
      publicKeyHex: result.publicKeyHex,
      ecdsaPubkey: result.ecdsaPubkey,
      eddsaPubkey: result.eddsaPubkey,
      signatureHex: result.signatureHex,
      signatureRecoveryHex: result.signatureRecoveryHex,
      rHex: result.rHex,
      sHex: result.sHex,
      signedInputHex: result.signedInputHex,
      expiresAt: accepted.expiresAt,
      error: _joinError(result.errorCode, result.errorMessage),
    );
  }

  final bool accepted;
  final String sessionId;
  final String keyId;
  final String publicKeyHex;
  final String ecdsaPubkey;
  final String eddsaPubkey;
  final String signatureHex;
  final String signatureRecoveryHex;
  final String rHex;
  final String sHex;
  final String signedInputHex;
  final String expiresAt;
  final String error;

  bool get hasSignature => signatureHex.isNotEmpty || rHex.isNotEmpty;
  bool get hasKey =>
      publicKeyHex.isNotEmpty ||
      ecdsaPubkey.isNotEmpty ||
      eddsaPubkey.isNotEmpty;
  bool get completed =>
      hasKey || hasSignature || signedInputHex.isNotEmpty || error.isNotEmpty;
}

String _joinError(String code, String message) {
  if (code.isEmpty) return message;
  if (message.isEmpty) return code;
  return '$code: $message';
}
