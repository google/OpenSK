#!/usr/bin/env bash
# Copyright 2019 Google LLC
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

echo "Checking formatting..."
cargo fmt --all -- --check
cd libraries/cbor
cargo fmt --all -- --check
cd ../..
cd libraries/crypto
cargo fmt --all -- --check
cd ../..

echo "Checking that CTAP2 builds properly..."
cargo check --release --target=thumbv7em-none-eabi
cargo check --release --target=thumbv7em-none-eabi --features with_ctap1
cargo check --release --target=thumbv7em-none-eabi --features debug_ctap
cargo check --release --target=thumbv7em-none-eabi --features panic_console
cargo check --release --target=thumbv7em-none-eabi --features debug_allocations
cargo check --release --target=thumbv7em-none-eabi --features ram_storage
cargo check --release --target=thumbv7em-none-eabi --features debug_ctap,with_ctap1
cargo check --release --target=thumbv7em-none-eabi --features debug_ctap,with_ctap1,panic_console,debug_allocations

echo "Checking that examples build properly..."
cargo check --release --target=thumbv7em-none-eabi --examples

echo "Checking that CTAP2 builds and links properly (1 set of features)..."
cargo build --release --target=thumbv7em-none-eabi --features with_ctap1

if [ -z "${TRAVIS_OS_NAME}" -o "${TRAVIS_OS_NAME}" = "linux" ]
then
  echo "Running unit tests on the desktop (release mode)..."
  cd libraries/cbor
  cargo test --release --features std
  cd ../..
  cd libraries/crypto
  RUSTFLAGS='-C target-feature=+aes' cargo test --release --features std,derive_debug
  cd ../..
  cargo test --release --features std

  echo "Running unit tests on the desktop (debug mode)..."
  cd libraries/cbor
  cargo test --features std
  cd ../..
  cd libraries/crypto
  RUSTFLAGS='-C target-feature=+aes' cargo test --features std,derive_debug
  cd ../..
  cargo test --features std

  echo "Running unit tests on the desktop (release mode + CTAP1)..."
  cargo test --release --features std,with_ctap1

  echo "Running unit tests on the desktop (debug mode + CTAP1)..."
  cargo test --features std,with_ctap1
fi
