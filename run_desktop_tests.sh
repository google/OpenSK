#!/usr/bin/env bash
# Copyright 2019-2026 Google LLC
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

set -ex

./fuzzing_setup.sh

MOST_FEATURES=config-command,ctap1,debug,ed25519,fingerprint

echo "Checking that OpenSK builds properly..."
cargo check --lib --target=thumbv7em-none-eabi
cargo check --lib --target=thumbv7em-none-eabi --features=config-command
cargo check --lib --target=thumbv7em-none-eabi --features=ctap1
cargo check --lib --target=thumbv7em-none-eabi --features=debug
cargo check --lib --target=thumbv7em-none-eabi --features=ed25519
cargo check --lib --target=thumbv7em-none-eabi --features=fingerprint
cargo check --lib --target=thumbv7em-none-eabi --features=led-1
cargo check --lib --target=thumbv7em-none-eabi --features="$MOST_FEATURES"
cargo check --manifest-path=libraries/opensk/Cargo.toml
cargo check --manifest-path=libraries/opensk/Cargo.toml --target=thumbv7em-none-eabi

echo "Checking fuzz targets..."
(cd libraries/opensk && cargo fuzz check)
(cd libraries/cbor && cargo fuzz check)

echo "Checking that CTAP2 builds and links properly..."
cargo build --release --target=thumbv7em-none-eabi --features=config-command,ctap1

echo "Checking Rust formatting..."
cargo fmt -- --check
cargo fmt --manifest-path libraries/opensk/Cargo.toml -- --check
cargo fmt --manifest-path libraries/opensk/fuzz/Cargo.toml -- --check
cargo fmt --manifest-path libraries/cbor/Cargo.toml -- --check
cargo fmt --manifest-path libraries/cbor/fuzz/Cargo.toml -- --check

echo "Checking Python formatting..."
uv run ruff check
uv run ruff format --check

echo "Running Clippy lints..."
cargo clippy --lib --tests --bins --benches --features=test -- -D warnings
cargo clippy --lib --tests --bins --benches --features=test,"$MOST_FEATURES" -- -D warnings
(cd libraries/opensk && cargo clippy --features=std -- -D warnings)
(cd libraries/opensk && cargo clippy --all-features -- -D warnings)
(cd libraries/cbor && cargo clippy -- -D warnings)

echo "Running OpenSK library unit tests..."
cd libraries/opensk
cargo test --no-default-features --features=std
cargo test --features=std,config_command,with_ctap1
cargo test --all-features
cd ../..

echo "Running other unit tests..."
cargo test --lib --features=test
cargo test --manifest-path=libraries/cbor/Cargo.toml

cargo audit
