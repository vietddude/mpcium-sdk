.PHONY: test mobile-test mobile-android mobile-android-sample proto-tools proto

ANDROID_API ?= 21
ORCH_REPO_DIR ?= ../mpcium-orch
ORCH_PROTO_REL_PATH ?= proto/orch_orchestration.proto

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
	@test -f "$(ORCH_REPO_DIR)/$(ORCH_PROTO_REL_PATH)" || (echo "missing $(ORCH_REPO_DIR)/$(ORCH_PROTO_REL_PATH). clone mpcium-orch first." && exit 1)
	PATH="$(PATH):$$(go env GOPATH)/bin" protoc -I "$(ORCH_REPO_DIR)" \
		--go_out=. --go_opt=module=github.com/fystack/mpcium-sdk \
		--go-grpc_out=. --go-grpc_opt=module=github.com/fystack/mpcium-sdk \
		"$(ORCH_REPO_DIR)/$(ORCH_PROTO_REL_PATH)"
