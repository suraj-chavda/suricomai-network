#!/bin/sh
# Run Foundry from the official image, pinned by digest, so nothing is installed on the host.
# Usage: contracts/run.sh "forge test -vv"
set -eu
IMAGE="ghcr.io/foundry-rs/foundry@sha256:4a16a86f41d30418fbdca47ce2868121bbb0aeaa0a34bde2dd1e2911c4be2464"
cd "$(dirname "$0")"
exec docker run --rm -v "$PWD:/work" -w /work "$IMAGE" "$@"
