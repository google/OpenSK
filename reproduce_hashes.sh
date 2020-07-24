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

rm -f reproducible/binaries.sha256sum
rm -f reproducible/elf2tab.txt

echo "Creating reproducible/reproduced.tar"
touch empty_file
tar -cvf reproducible/reproduced.tar empty_file
rm empty_file

echo "Building sha256sum tool..."
cargo build --manifest-path third_party/tock/tools/sha256sum/Cargo.toml

echo "Computing SHA-256 sums of the boards..."
for board in nrf52840dk nrf52840_dongle nrf52840_dongle_dfu nrf52840_mdk_dfu
do
  BOARD=$board ./reproduce_board.sh
done

echo "Computing SHA-256 sum of the TAB file..."
./third_party/tock/tools/sha256sum/target/debug/sha256sum target/tab/ctap2.tab >> reproducible/binaries.sha256sum
tar -rvf reproducible/reproduced.tar target/tab/ctap2.tab

tar -rvf reproducible/reproduced.tar reproducible/elf2tab.txt
tar -rvf reproducible/reproduced.tar reproducible/binaries.sha256sum
