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

# Ensure the submodules are pulled and up-to-date
git submodule update --init

done_text="$(tput bold)DONE.$(tput sgr0)"

# Apply patches to kernel. Do that in a sub-shell
(
  cd third_party/tock/ && \
  for p in ../../patches/tock/[0-9][0-9]-*.patch
  do
    echo -n '[-] Applying patch "'$(basename $p)'"... '
    git apply "$p" && echo $done_text
  done
)

# Now apply patches to libtock-rs. Do that in a sub-shell
(
  cd third_party/libtock-rs/ && \
  for p in ../../patches/libtock-rs/[0-9][0-9]-*.patch
  do
    echo -n '[-] Applying patch "'$(basename $p)'"... '
    git apply "$p" && echo $done_text
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
