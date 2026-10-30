#!/bin/sh
# Prove that the crates meant to ship contain no software quote and no development key.
#   1. Build them in release mode without the `lab` feature.
#   2. Search the compiled code (not compiler metadata) for strings only the stand-ins contain.
#   3. Run the same search on a build WITH the feature, which must find them (a control that
#      shows the search can fail).
#   4. Confirm the development node refuses to build without the feature.
set -eu
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

MARKERS="suricomai-lab-quote suricomai.lab-quote suricomai lab key"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Print the markers found in the compiled code of an rlib.
scan() {
  dir="$WORK/$(basename "$1").$$"
  mkdir -p "$dir"
  (cd "$dir" && ar x "$ROOT/$1" 2>/dev/null || true)
  for obj in "$dir"/*.o; do
    [ -f "$obj" ] || continue
    for marker in suricomai-lab-quote "suricomai.lab-quote" "suricomai lab key"; do
      if strings "$obj" | grep -q "$marker"; then echo "$marker"; fi
    done
  done | sort -u
}

fail=0
for crate in suricomai-envelope suricomai-escrow suricomai-attestor; do
  cargo build -q --release -p "$crate"
  lib="target/release/lib$(echo "$crate" | tr - _).rlib"
  found="$(scan "$lib")"
  if [ -n "$found" ]; then
    echo "FAIL: $crate contains: $found"
    fail=1
  fi
done

cargo build -q --release -p suricomai-envelope --features lab
control="$(scan target/release/libsuricomai_envelope.rlib)"
if [ -z "$control" ]; then
  echo "FAIL: the search did not find the software quote in a build that has it"
  fail=1
fi

if cargo build -q -p suricomai-runtime >/dev/null 2>&1; then
  echo "FAIL: the development node built without the lab feature"
  fail=1
fi

cargo build -q --release -p suricomai-envelope   # leave the shipping build in place
[ "$fail" = 0 ] && echo "release check passed: the shipping crates contain no software quote and no development key"
exit "$fail"
