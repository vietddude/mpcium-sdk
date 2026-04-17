.PHONY: test mobile-android mobile-android-sample

ANDROID_API ?= 21

test:
	GOCACHE=$(CURDIR)/.gocache go test ./...

mobile-android:
	@ANDROID_MIN_API=$(ANDROID_API) ./scripts/build-mobile.sh

mobile-android-sample:
	@command -v gradle >/dev/null 2>&1 || (echo "gradle is required to build examples/mobile-android" && exit 1)
	cd examples/mobile-android && gradle assembleDebug
