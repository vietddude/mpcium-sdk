.PHONY: test mobile-test mobile-android mobile-android-sample proto-tools proto

ANDROID_API ?= 21

test:
	GOCACHE=$(CURDIR)/.gocache go test ./...

mobile-test:
	cd bindings/mobile && GOCACHE=$(CURDIR)/../../.gocache go test ./...

mobile-android:
	@ANDROID_MIN_API=$(ANDROID_API) ./scripts/build-mobile.sh

mobile-android-sample:
	cd examples/mobile-android && ./gradlew assembleDebug

proto-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

proto:
	cd integrations/coordinator-grpc && PATH="$(PATH):$$(go env GOPATH)/bin" protoc -I proto \
		--go_out=. --go_opt=module=github.com/fystack/mpcium-sdk/integrations/coordinator-grpc \
		--go-grpc_out=. --go-grpc_opt=module=github.com/fystack/mpcium-sdk/integrations/coordinator-grpc \
		proto/coordinator_orchestration.proto
