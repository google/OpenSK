#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Adapted from https://github.com/google/wasefire/blob/main/scripts/publish.sh

set -e
export LC_COLLATE=C

# Ensure we are in the root directory of OpenSK.
REPO_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
cd "$REPO_ROOT"

_LOG="$(printf '\033')"
_log() { echo "$_LOG[$1m$2:$_LOG[m $3"; }
x() { ( set -x; "$@" ); }
i() { _log '1;36' Info "$*"; }
w() { _log '1;33' Warn "$*"; }
d() { _log '1;32' Done "$*"; exit 0; }
e() { _log '1;31' Error "$*"; exit 1; }

usage() {
  cat <<EOF
Usage: $0 [--dry-run | --no-dry-run] [cbor | opensk]

Publishes OpenSK library crates (cbor, then opensk) to crates.io.

Options:
  --dry-run     Check crates.io versions and run 'cargo publish --dry-run'
                without uploading (default).
  --no-dry-run  Run pre-publish checks/tests and publish unpublished crate
                versions to crates.io.
  -h, --help    Show this help message.
EOF
}

DRY_RUN=true
CRATES=()

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --no-dry-run) DRY_RUN=false ;;
    cbor|opensk) CRATES+=("$arg") ;;
    -h|--help) usage; exit 0 ;;
    *) usage; e "Unknown argument: $arg" ;;
  esac
done

if [ "${#CRATES[@]}" -eq 0 ]; then
  CRATES=(cbor opensk)
fi

package_field() {
  sed -n '/^\[package\]$/,/^\[/{s/^'"$1"' = "\(.*\)"$/\1/p;}' "$2"
}

cargo_info_version() {
  cargo info --registry=crates-io -q "$1" 2>/dev/null \
    | sed -n 's/^version: .* (latest \(.*\))$/\1/p; t; s/^version: //p'
}

for crate in cbor opensk; do
  manifest="libraries/$crate/Cargo.toml"
  for field in name version license edition description repository readme; do
    val="$(package_field "$field" "$manifest")"
    [ -n "$val" ] || e "$manifest is missing required package field '$field'"
  done
  readme_file="$(package_field readme "$manifest")"
  [ -f "libraries/$crate/$readme_file" ] || e "libraries/$crate/$readme_file does not exist"
  [ -f "libraries/$crate/LICENSE" ] || e "libraries/$crate/LICENSE does not exist"
done

cbor_ver="$(package_field version libraries/cbor/Cargo.toml)"
opensk_cbor_ver="$(sed -n 's/^sk-cbor = {.*version = "\([^"]*\)".*}$/\1/p' libraries/opensk/Cargo.toml)"
[ "$opensk_cbor_ver" = "$cbor_ver" ] \
  || e "libraries/opensk/Cargo.toml depends on sk-cbor '$opensk_cbor_ver', expected '$cbor_ver'"

for git_dir in . third_party/wasefire; do
  if [ -e "$git_dir/.git" ] && [ "$(git -C "$git_dir" config --get extensions.refstorage || true)" = "reftable" ]; then
    e "Git repository '$git_dir' uses reftable ref storage, which Cargo cannot read yet. Run: git -C $git_dir refs migrate --ref-format=files"
  fi
done

verify_crate() {
  local crate="$1"
  x cargo fmt -- --check
  case "$crate" in
    cbor)
      x cargo check --target=thumbv7em-none-eabi
      x cargo clippy -- -D warnings
      x cargo test
      ;;
    opensk)
      x cargo check
      x cargo check --target=thumbv7em-none-eabi
      x cargo clippy --features=std -- -D warnings
      x cargo clippy --all-features -- -D warnings
      x cargo test --no-default-features --features=std
      x cargo test --features=std,config_command,ctap1
      x cargo test --all-features
      ;;
  esac
}

for crate in "${CRATES[@]}"; do
  [ -z "$(git status -s "libraries/$crate")" ] || e "libraries/$crate has uncommitted changes"
  (
    cd "libraries/$crate"
    name="$(package_field name Cargo.toml)"
    current="$(package_field version Cargo.toml)"
    latest="$(cargo_info_version "$name")"
    if [ "$current" = "$latest" ]; then
      i "Skipping $crate ($name) already published at $latest"
      exit 0
    fi
    if [ "$DRY_RUN" = true ]; then
      i "Would publish $crate ($name) from ${latest:--} to $current"
      if [ "$crate" = "opensk" ] && [ "$(cargo_info_version sk-cbor)" != "$cbor_ver" ]; then
        x cargo package --list
        w "Skipping 'cargo publish --dry-run' for opensk: sk-cbor $cbor_ver is not on crates.io yet"
      else
        x cargo publish --dry-run
      fi
    else
      i "Verify and publish $crate ($name) from ${latest:--} to $current"
      verify_crate "$crate"
      x cargo publish
    fi
  )
done

if [ "$DRY_RUN" = true ]; then
  d "Run with --no-dry-run to actually publish"
fi
d "Published requested crates"
