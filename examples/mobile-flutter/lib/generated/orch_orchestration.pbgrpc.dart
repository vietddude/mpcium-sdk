import 'package:grpc/grpc.dart' as grpc;

import 'orch_orchestration.pb.dart' as pb;

class OrchOrchestrationClient extends grpc.Client {
  OrchOrchestrationClient(
    super.channel, {
    super.options,
    super.interceptors,
  });

  static final _$keygen = grpc.ClientMethod<pb.KeygenRequest, pb.RequestAccepted>(
    '/orch.v1.Orchestration/Keygen',
    (pb.KeygenRequest value) => value.writeToBuffer(),
    (List<int> value) => pb.RequestAccepted.fromBuffer(value),
  );

  static final _$sign = grpc.ClientMethod<pb.SignRequest, pb.RequestAccepted>(
    '/orch.v1.Orchestration/Sign',
    (pb.SignRequest value) => value.writeToBuffer(),
    (List<int> value) => pb.RequestAccepted.fromBuffer(value),
  );

  static final _$waitSessionResult =
      grpc.ClientMethod<pb.SessionLookup, pb.SessionResult>(
    '/orch.v1.Orchestration/WaitSessionResult',
    (pb.SessionLookup value) => value.writeToBuffer(),
    (List<int> value) => pb.SessionResult.fromBuffer(value),
  );

  grpc.ResponseFuture<pb.RequestAccepted> keygen(
    pb.KeygenRequest request, {
    grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$keygen, request, options: options);
  }

  grpc.ResponseFuture<pb.RequestAccepted> sign(
    pb.SignRequest request, {
    grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$sign, request, options: options);
  }

  grpc.ResponseFuture<pb.SessionResult> waitSessionResult(
    pb.SessionLookup request, {
    grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$waitSessionResult, request, options: options);
  }
}
