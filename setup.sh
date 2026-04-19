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

# Ensure the script doesn't fail on Github workflows
export TERM=${TERM:-vt100}
done_text="$(tput bold)DONE.$(tput sgr0)"

set -e

# Check that rustup and pip3 are installed
check_command () {
  if ! which "$1" >/dev/null
  then
    echo "Missing $1 command. Follow the steps under $2 to install it."
    exit 1
  fi
}
check_command rustup "https://rustup.rs/"
check_command uv "https://docs.astral.sh/uv/getting-started/installation/"

# Ensure we have certificates, keys, etc. so that the tests can run
source tools/gen_key_materials.sh
generate_pki N
if [ ! -f "crypto_data/opensk.key" -o ! -f "crypto_data/opensk_cert.pem" ]
then
  generate_new_batch
fi

rustup show
rustup install stable
cargo +stable install cargo-audit
