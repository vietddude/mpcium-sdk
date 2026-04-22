# Mobile Android Sample

This sample shows the Android host structure for:

- native MQTT transport adapter (Eclipse Paho)
- native secure store adapter (SQLCipher)
- Go mobile facade integration (`mobile` package AAR)

## Build prerequisites

1. Start a local MQTT broker for the emulator:

```bash
docker run --rm -p 1883:1883 eclipse-mosquitto:2 mosquitto -c /mosquitto-no-auth.conf
```

2. Build mobile binding AAR:

```bash
make mobile-android
```

3. Ensure AAR exists at `bindings/mobile/dist/mpcium-mobile.aar`.

4. Build sample:

```bash
cd examples/mobile-android
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew assembleDebug
```

5. Install and run the debug APK on an Android emulator, then tap **Start runtime**.

## Notes

- The emulator reaches the host MQTT broker at `tcp://10.0.2.2:1883`.
- `MainActivity` registers native adapters, creates `mobile.Client`, starts the runtime, and polls runtime events.
- The demo coordinator public key is fixed and only intended to satisfy runtime bootstrap validation.
- Adapter classes (`NativeTransportAdapter`, `NativeStoreAdapter`) implement the generated Go mobile facade interfaces.
