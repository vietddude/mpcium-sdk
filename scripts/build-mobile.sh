#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_BUILD_DIR="${REPO_ROOT}/dist"
OUTPUT_AAR="${ANDROID_BUILD_DIR}/mpcium-mobile.aar"
ANDROID_MIN_API="${ANDROID_MIN_API:-21}"
ANDROID_TARGETS="${ANDROID_TARGETS:-android/arm64,android/amd64}"
GOMOBILEDIR="${GOMOBILEDIR:-${REPO_ROOT}/build/gomobile}"

# --- SDK / NDK auto-detection ---
: "${ANDROID_SDK_ROOT:=${ANDROID_HOME:-${HOME}/Library/Android/sdk}}"
export ANDROID_HOME="${ANDROID_SDK_ROOT}"

if [[ -z "${JAVA_HOME:-}" && -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ]]; then
    export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    ndk_root="${ANDROID_SDK_ROOT}/ndk"
    [[ -d "${ndk_root}" ]] && \
        export ANDROID_NDK_HOME="$(ls -1d "${ndk_root}"/* 2>/dev/null | tail -1)" NDK_HOME="${ANDROID_NDK_HOME}"
fi

# --- Validation ---
die() { echo "$*" >&2; exit 1; }

[[ -d "${ANDROID_SDK_ROOT}" ]]  || die "ANDROID_SDK_ROOT not set or invalid. Please install Android SDK."
[[ -d "${ANDROID_NDK_HOME:-}" ]] || die "ANDROID_NDK_HOME not set or invalid. Install NDK via sdkmanager."
command -v javac >/dev/null 2>&1 || die "javac required. Install JDK 17+ and add JAVA_HOME/bin to PATH."
(( ANDROID_MIN_API >= 21 && ANDROID_MIN_API <= 34 )) || die "ANDROID_MIN_API must be 21–34."

# --- Go toolchain / module safety ---
GO_BIN="${GO_BIN:-$(command -v go || true)}"
[[ -n "${GO_BIN}" ]] || die "Go toolchain not found in PATH."

case " ${GOFLAGS:-} " in
    *" -mod=readonly "*) ;;
    *" -mod="*) die "GOFLAGS must not override -mod=readonly for mobile builds." ;;
    *) export GOFLAGS="${GOFLAGS:+${GOFLAGS} }-mod=readonly" ;;
esac

go_cmd() { "${GO_BIN}" "$@"; }
gomobile_cmd() { GOMOBILEDIR="${GOMOBILEDIR}" gomobile "$@"; }

GOBIN_PATH="$(go_cmd env GOBIN)"
[[ -n "${GOBIN_PATH}" ]] || GOBIN_PATH="$(go_cmd env GOPATH)/bin"
mkdir -p "${GOBIN_PATH}"
export PATH="${GOBIN_PATH}:${PATH}"

# --- Ensure gomobile / gobind ---
go_install() {
    command -v "$1" >/dev/null 2>&1 && return
    echo "Installing $1..."
    GO111MODULE=on go_cmd install "$2"
}

go_install gomobile golang.org/x/mobile/cmd/gomobile@latest
go_install gobind golang.org/x/mobile/cmd/gobind@latest

if ! go_cmd list golang.org/x/mobile/bind >/dev/null 2>&1; then
    die "Missing module dependency: golang.org/x/mobile/bind. Run once: go get golang.org/x/mobile/bind && go mod tidy"
fi

if ! go_cmd list ./mobile >/dev/null 2>&1; then
    die "Module graph is not read-only clean for ./mobile. Sync deps first with go mod tidy (or add the missing requirements manually)."
fi

# --- Build ---
[[ "${SKIP_GOMOBILE_INIT:-0}" == "1" ]] || { echo "Running gomobile init..."; gomobile_cmd init -v; }

mkdir -p "${ANDROID_BUILD_DIR}"
cd "${REPO_ROOT}"

echo "Building Android AAR..."
gomobile_cmd bind \
    -target="${ANDROID_TARGETS}" \
    -androidapi="${ANDROID_MIN_API}" \
    -o "${OUTPUT_AAR}" \
    ./mobile

echo "Done: ${OUTPUT_AAR}"
