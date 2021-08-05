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

echo "Board: $BOARD"
echo "========================================" >> reproducible/elf2tab.txt
echo "Board: $BOARD" >> reproducible/elf2tab.txt
echo "----------------------------------------" >> reproducible/elf2tab.txt

./deploy.py --verbose-build --board=$BOARD --no-app --programmer=none
./third_party/tock/tools/sha256sum/target/debug/sha256sum third_party/tock/target/thumbv7em-none-eabi/release/$BOARD.bin >> reproducible/binaries.sha256sum
tar -rvf reproducible/reproduced.tar third_party/tock/target/thumbv7em-none-eabi/release/$BOARD.bin

./deploy.py --verbose-build --board=$BOARD --opensk --programmer=none --elf2tab-output=reproducible/elf2tab.txt
./third_party/tock/tools/sha256sum/target/debug/sha256sum target/${BOARD}_merged.hex >> reproducible/binaries.sha256sum
tar -rvf reproducible/reproduced.tar target/${BOARD}_merged.hex
