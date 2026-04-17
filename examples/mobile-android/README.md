# Mobile Android Sample

This sample shows the Android host structure for:

- native MQTT transport adapter (Eclipse Paho)
- native secure store adapter (SQLCipher)
- Go mobile facade integration (`mobile` package AAR)

## Build prerequisites

1. Build mobile binding AAR:

```bash
make mobile-android
```

2. Ensure AAR exists at `dist/mpcium-mobile.aar`.

3. Build sample:

```bash
make mobile-android-sample
```

## Notes

- `MainActivity` currently includes a bootstrap placeholder where Go mobile binding calls should be wired.
- Adapter classes (`NativeTransportAdapter`, `NativeStoreAdapter`) follow the method contract required by the new mobile facade registration APIs.
