import 'package:grpc/grpc.dart' as grpc;

import 'coordinator_orchestration.pb.dart' as pb;

class CoordinatorOrchestrationClient extends grpc.Client {
  CoordinatorOrchestrationClient(
    super.channel, {
    super.options,
    super.interceptors,
  });

  static final _$keygen = grpc.ClientMethod<pb.KeygenRequest, pb.RequestAccepted>(
    '/coordinator.v1.CoordinatorOrchestration/Keygen',
    (pb.KeygenRequest value) => value.writeToBuffer(),
    (List<int> value) => pb.RequestAccepted.fromBuffer(value),
  );

  static final _$sign = grpc.ClientMethod<pb.SignRequest, pb.RequestAccepted>(
    '/coordinator.v1.CoordinatorOrchestration/Sign',
    (pb.SignRequest value) => value.writeToBuffer(),
    (List<int> value) => pb.RequestAccepted.fromBuffer(value),
  );

  static final _$waitSessionResult =
      grpc.ClientMethod<pb.SessionLookup, pb.SessionResult>(
    '/coordinator.v1.CoordinatorOrchestration/WaitSessionResult',
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
