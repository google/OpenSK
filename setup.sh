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

# Ensure the script doesn't fail on Github workflows
export TERM=${TERM:-vt100}
done_text="$(tput bold)DONE.$(tput sgr0)"

set -e

# Check that rustup and pip3 are installed
check_command () {
  if ! which "$1" >/dev/null
  then
    echo "Missing $1 command.$2"
    exit 1
  fi
}
check_command rustup " Follow the steps under https://rustup.rs/ to install it."
check_command pip3

# Ensure the submodules are pulled and up-to-date
git submodule update --init

patch_conflict_detected () {
  cat <<EOF

This script cannot be run twice without reverting the patches.

To do so, follow these instructions:
1. Commit any changes you want to save.
2. Run the ./reset.sh script to revert all uncommitted changes.
3. Run the ./setup.sh script again.
EOF
  exit 1
}

# Apply patches to kernel. Do that in a sub-shell
(
  cd third_party/tock/ && \
  for p in ../../patches/tock/[0-9][0-9]-*.patch
  do
    echo -n '[-] Applying patch "'$(basename $p)'"... '
    if git apply "$p"
    then
      echo $done_text
    else
      patch_conflict_detected
    fi
  done
)

# Now apply patches to libtock-rs. Do that in a sub-shell
(
  cd third_party/libtock-rs/ && \
  for p in ../../patches/libtock-rs/[0-9][0-9]-*.patch
  do
    echo -n '[-] Applying patch "'$(basename $p)'"... '
    if git apply "$p"
    then
      echo $done_text
    else
      patch_conflict_detected
    fi
  done
)

# Ensure we have certificates, keys, etc. so that the tests can run
source tools/gen_key_materials.sh
generate_crypto_materials N

rustup install $(head -n 1 rust-toolchain)
pip3 install --user --upgrade tockloader
rustup target add thumbv7em-none-eabi

# Install dependency to create applications.
cargo install elf2tab
