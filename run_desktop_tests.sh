#!/usr/bin/env bash
# Copyright 2019-2023 Google LLC
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
# Excludes std
MOST_FEATURES=config_command,debug_allocations,debug_ctap,panic_console,verbose,with_ctap1,vendor_hid,ed25519

echo "Checking that OpenSK builds properly..."
cargo check --release --target=thumbv7em-none-eabi
cargo check --release --target=thumbv7em-none-eabi --features config_command
cargo check --release --target=thumbv7em-none-eabi --features debug_allocations
cargo check --release --target=thumbv7em-none-eabi --features debug_ctap
cargo check --release --target=thumbv7em-none-eabi --features panic_console
cargo check --release --target=thumbv7em-none-eabi --features verbose
cargo check --release --target=thumbv7em-none-eabi --features with_ctap1
cargo check --release --target=thumbv7em-none-eabi --features with_nfc
cargo check --release --target=thumbv7em-none-eabi --features vendor_hid
cargo check --release --target=thumbv7em-none-eabi --features ed25519
cargo check --release --target=thumbv7em-none-eabi --features rust_crypto
cargo check --release --target=thumbv7em-none-eabi --features "$MOST_FEATURES"
cargo check --release --target=thumbv7em-none-eabi --examples
cargo check --release --target=thumbv7em-none-eabi --examples --features with_nfc
cargo check --release --target=thumbv7em-none-eabi --manifest-path bootloader/Cargo.toml
cargo check --release --manifest-path tools/heapviz/Cargo.toml

echo "Checking Rust formatting..."
cargo fmt -- --check
cargo fmt --manifest-path libraries/opensk/Cargo.toml -- --check
cargo fmt --manifest-path libraries/opensk/fuzz/Cargo.toml -- --check
cargo fmt --manifest-path libraries/cbor/Cargo.toml -- --check
cargo fmt --manifest-path libraries/cbor/fuzz/Cargo.toml -- --check
cargo fmt --manifest-path libraries/persistent_store/Cargo.toml -- --check
cargo fmt --manifest-path libraries/persistent_store/fuzz/Cargo.toml -- --check
cargo fmt --manifest-path libraries/crypto/Cargo.toml -- --check
cargo fmt --manifest-path tools/heapviz/Cargo.toml -- --check
cargo fmt --manifest-path bootloader/Cargo.toml -- --check

echo "Checking Python formatting..."
py_virtual_env/bin/pylint --score=n `git ls-files --deduplicate --exclude-standard --full-name '*.py'`
py_virtual_env/bin/yapf --style=yapf --recursive --exclude py_virtual_env --exclude third_party --diff .

echo "Running Clippy lints..."
cargo clippy --lib --tests --bins --benches --features std -- -D warnings
cargo clippy --lib --tests --bins --benches --features std,"$MOST_FEATURES" -- -D warnings
(cd libraries/opensk && cargo clippy --features std -- -D warnings)
(cd libraries/opensk && cargo clippy --features std,config_command,debug_ctap,with_ctap1,vendor_hid,ed25519,rust_crypto  -- -D warnings)
(cd libraries/cbor && cargo clippy -- -D warnings)
# Uncomment when persistent store is fixed:
# (cd libraries/persistent_store && cargo clippy --features std -- -D warnings)
# Probably not worth fixing:
# (cd libraries/crypto && cargo clippy --features std -- -D warnings)

echo "Checking that fuzz targets..."
(cd libraries/opensk && cargo fuzz check)
(cd libraries/cbor && cargo fuzz check)
(cd libraries/persistent_store && cargo fuzz check)

echo "Building sha256sum tool..."
cargo build --manifest-path third_party/tock/tools/sha256sum/Cargo.toml

echo "Checking that CTAP2 builds and links properly (1 set of features)..."
cargo build --release --target=thumbv7em-none-eabi --features config_command,with_ctap1
./third_party/tock/tools/sha256sum/target/debug/sha256sum target/thumbv7em-none-eabi/release/ctap2

echo "Running OpenSK library unit tests..."
cd libraries/opensk
cargo test --features std
cargo test --features std,config_command,with_ctap1
cargo test --all-features
cd ../..

echo "Running other unit tests..."
cargo test --lib --tests --bins --benches --features std
cargo test --lib --tests --bins --benches --all-features
cargo test --manifest-path libraries/cbor/Cargo.toml
cargo test --manifest-path libraries/persistent_store/Cargo.toml --features std
# Running release mode to speed up. This library is legacy anyway.
cargo test --manifest-path libraries/crypto/Cargo.toml --features std --release
cargo test --manifest-path tools/heapviz/Cargo.toml

echo "Checking that boards build properly..."
make -C third_party/tock/boards/nordic/nrf52840dk_opensk
make -C third_party/tock/boards/nordic/nrf52840_dongle_opensk
make -C third_party/tock/boards/nordic/nrf52840_dongle_dfu
make -C third_party/tock/boards/nordic/nrf52840_mdk_dfu

echo "Checking deployment of boards..."
./deploy.py --board=nrf52840dk_opensk --no-app --programmer=none
./deploy.py --board=nrf52840_dongle_opensk --no-app --programmer=none
./deploy.py --board=nrf52840_dongle_dfu --no-app --programmer=none
./deploy.py --board=nrf52840_mdk_dfu --no-app --programmer=none

echo "Check app deployment"
./deploy.py --board=nrf52840dk_opensk --programmer=none --opensk
./deploy.py --board=nrf52840dk_opensk --programmer=none --crypto_bench
./deploy.py --board=nrf52840dk_opensk --programmer=none --store_latency
./deploy.py --board=nrf52840dk_opensk --programmer=none --erase_storage
./deploy.py --board=nrf52840dk_opensk --programmer=none --panic_test
./deploy.py --board=nrf52840dk_opensk --programmer=none --oom_test
./deploy.py --board=nrf52840dk_opensk --programmer=none --console_test
./deploy.py --board=nrf52840dk_opensk --programmer=none --nfct_test --nfc

cargo audit
