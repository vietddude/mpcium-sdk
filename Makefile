.PHONY: test mobile-android mobile-android-sample

test:
	GOCACHE=$(CURDIR)/.gocache go test ./...

mobile-android:
	@command -v gomobile >/dev/null 2>&1 || (echo "gomobile is required (install: go install golang.org/x/mobile/cmd/gomobile@latest)" && exit 1)
	@mkdir -p dist
	gomobile bind -target=android -o dist/mpcium-mobile.aar ./mobile

mobile-android-sample:
	@command -v gradle >/dev/null 2>&1 || (echo "gradle is required to build examples/mobile-android" && exit 1)
	cd examples/mobile-android && gradle assembleDebug
