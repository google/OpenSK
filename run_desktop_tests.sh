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
cd libraries/persistent_store
cargo fmt --all -- --check
cd ../..
cd tools/heapviz
cargo fmt --all -- --check
cd ../..

echo "Running Clippy lints..."
cargo clippy --all-targets --features std --features with_nfc -- -A clippy::new_without_default -D warnings

echo "Building sha256sum tool..."
cargo build --manifest-path third_party/tock/tools/sha256sum/Cargo.toml
echo "Checking that heapviz tool builds properly..."
cargo build --manifest-path tools/heapviz/Cargo.toml
echo "Testing heapviz tool..."
cargo test --manifest-path tools/heapviz/Cargo.toml

echo "Checking that CTAP2 builds properly..."
cargo check --release --target=thumbv7em-none-eabi
cargo check --release --target=thumbv7em-none-eabi --features with_ctap1
cargo check --release --target=thumbv7em-none-eabi --features with_ctap2_1
cargo check --release --target=thumbv7em-none-eabi --features debug_ctap
cargo check --release --target=thumbv7em-none-eabi --features panic_console
cargo check --release --target=thumbv7em-none-eabi --features debug_allocations
cargo check --release --target=thumbv7em-none-eabi --features ram_storage
cargo check --release --target=thumbv7em-none-eabi --features verbose
cargo check --release --target=thumbv7em-none-eabi --features debug_ctap,with_ctap1
cargo check --release --target=thumbv7em-none-eabi --features debug_ctap,with_ctap1,panic_console,debug_allocations,verbose

echo "Checking that examples build properly..."
cargo check --release --target=thumbv7em-none-eabi --examples --features with_nfc

echo "Checking that fuzz targets build properly..."
cargo fuzz build
cd libraries/cbor
cargo fuzz build
cd ../..

echo "Checking that CTAP2 builds and links properly (1 set of features)..."
cargo build --release --target=thumbv7em-none-eabi --features with_ctap1
./third_party/tock/tools/sha256sum/target/debug/sha256sum target/thumbv7em-none-eabi/release/ctap2

echo "Checking that supported boards build properly..."
make -C third_party/tock/boards/nordic/nrf52840dk
make -C third_party/tock/boards/nordic/nrf52840_dongle

echo "Checking that other boards build properly..."
make -C third_party/tock/boards/nordic/nrf52840_dongle_dfu
make -C third_party/tock/boards/nordic/nrf52840_mdk_dfu

echo "Checking deployment of supported boards..."
./deploy.py --board=nrf52840dk --no-app --programmer=none
./deploy.py --board=nrf52840_dongle --no-app --programmer=none

echo "Checking deployment of other boards..."
./deploy.py --board=nrf52840_dongle_dfu --no-app --programmer=none
./deploy.py --board=nrf52840_mdk_dfu --no-app --programmer=none

if [ -z "${TRAVIS_OS_NAME}" -o "${TRAVIS_OS_NAME}" = "linux" ]
then
  echo "Running unit tests on the desktop (release mode)..."
  cd libraries/cbor
  cargo test --release --features std
  cd ../..
  cd libraries/crypto
  RUSTFLAGS='-C target-feature=+aes' cargo test --release --features std,derive_debug
  cd ../..
  cd libraries/persistent_store
  cargo test --release --features std
  cd ../..
  cargo test --release --features std

  echo "Running unit tests on the desktop (debug mode)..."
  cd libraries/cbor
  cargo test --features std
  cd ../..
  cd libraries/crypto
  RUSTFLAGS='-C target-feature=+aes' cargo test --features std,derive_debug
  cd ../..
  cd libraries/persistent_store
  cargo test --features std
  cd ../..
  cargo test --features std

  echo "Running unit tests on the desktop (release mode + CTAP1)..."
  cargo test --release --features std,with_ctap1

  echo "Running unit tests on the desktop (debug mode + CTAP1)..."
  cargo test --features std,with_ctap1

  echo "Running unit tests on the desktop (release mode + CTAP2.1)..."
  cargo test --release --features std,with_ctap2_1

  echo "Running unit tests on the desktop (debug mode + CTAP2.1)..."
  cargo test --features std,with_ctap2_1

  echo "Running unit tests on the desktop (release mode + CTAP1 + CTAP2.1)..."
  cargo test --release --features std,with_ctap1,with_ctap2_1

  echo "Running unit tests on the desktop (debug mode + CTAP1 + CTAP2.1)..."
  cargo test --features std,with_ctap1,with_ctap2_1
fi
