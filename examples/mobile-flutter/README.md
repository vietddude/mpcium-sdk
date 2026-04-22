# MPCIUM Flutter Android Sample

This sample runs the same gomobile Android runtime used by `examples/mobile-android`,
but exposes it to Flutter through a thin Kotlin bridge. It also acts as a
native Dart gRPC client for coordinator orchestration.

The app has three screens:

- **Connect**: configure MQTT relay and coordinator gRPC endpoint, start the
  mobile MPC runtime, show/copy the mobile identity public key.
- **Keygen**: submit a gRPC keygen request with threshold, protocol, wallet ID,
  peer participants, and the mobile participant auto-added from runtime identity.
- **Sign**: submit a gRPC sign request for a hex message, approve mobile SIGN
  requests from runtime events, and display the returned signature fields.

## Prerequisites

1. Install Flutter and Android Studio.
2. Start a local MQTT broker for the Android emulator:

```bash
docker run --rm -p 1883:1883 eclipse-mosquitto:2 mosquitto -c /mosquitto-no-auth.conf
```

3. Start your relay/coordinator stack. The Flutter app assumes:

```text
MQTT relay: tcp://10.0.2.2:1883
Coordinator gRPC: 10.0.2.2:50051
```

4. Build the gomobile AAR from the repository root:

```bash
make mobile-android
```

5. Ensure this file exists:

```text
bindings/mobile/dist/mpcium-mobile.aar
```

## Run

From the repository root, build the gomobile AAR first:

```bash
make mobile-android
```

Then start an Android emulator:

```bash
cd examples/mobile-flutter
flutter emulators
flutter emulators --launch Medium_Phone_API_36.1
flutter devices
```

Run the Flutter app on the emulator:

```bash
cd examples/mobile-flutter
flutter pub get
flutter run -d emulator-5554
```

For readable app logs, keep `flutter run` open and tail only the sample tag from
another terminal:

```bash
adb logcat -c
adb logcat -s MpciumFlutter:I '*:S'
```

The unfiltered Flutter debug terminal can include Android runtime noise such as
`FlutterJNI`, `Choreographer`, `nativeloader`, and `GoLog`.

The Android Gradle project imports `../../bindings/mobile/dist/mpcium-mobile.aar` directly. Dart
talks to the runtime through:

- `MethodChannel("mpcium_sdk")` for commands.
- `EventChannel("mpcium_sdk/events")` for native log and runtime event batches.
- Dart gRPC for coordinator orchestration.

The MVP coordinator contract is in:

```text
../../integrations/coordinator-grpc/proto/coordinator_orchestration.proto
```

The current Dart gRPC shim in `lib/generated/` is hand-written because `protoc`
is not installed in this environment. When the server proto is finalized, replace
those files with generated Dart output:

```bash
protoc --dart_out=grpc:lib/generated -I ../../integrations/coordinator-grpc/proto ../../integrations/coordinator-grpc/proto/coordinator_orchestration.proto
```

If your shell does not have Flutter on `PATH`, call the SDK binary directly:

```bash
/Users/viet/development/flutter/bin/flutter pub get
/Users/viet/development/flutter/bin/flutter run -d emulator-5554
```

If `flutter run` builds the APK but reports that it cannot find the output file,
install and launch the generated debug APK manually:

```bash
adb install -r android/app/build/outputs/flutter-apk/app-debug.apk
adb shell monkey -p com.fystack.mpciumflutter -c android.intent.category.LAUNCHER 1
```

To confirm the app is running:

```bash
adb shell pidof com.fystack.mpciumflutter
adb shell dumpsys window | grep com.fystack.mpciumflutter
```

## Notes

- This sample is Android-only.
- The emulator reaches the host MQTT broker at `tcp://10.0.2.2:1883`.
- Default node ID is `flutter-sample-01`, so it can run next to the native Android sample.
- Keygen/sign buttons are disabled until the mobile runtime is connected.
