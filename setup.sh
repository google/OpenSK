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
PY_VENV_NAME=py_virtual_env
PYTHON="$PY_VENV_NAME"/bin/python
PIP="$PY_VENV_NAME"/bin/pip

set -e

# Ensure the submodules are pulled and up-to-date, and apply patches
./setup-submodules.sh

# Check that rustup and pip3 are installed
check_command () {
  if ! which "$1" >/dev/null
  then
    echo "Missing $1 command.$2"
    exit 1
  fi
}
check_command rustup " Follow the steps under https://rustup.rs/ to install it."
python3 -m venv "$PY_VENV_NAME"
"$PYTHON" -m pip install --upgrade pip setuptools wheel
check_command "$PIP"

# Ensure we have certificates, keys, etc. so that the tests can run
source tools/gen_key_materials.sh
generate_crypto_materials N

rustup show
# Nightly is used for testing and fuzzing libraries
rustup install nightly 
"$PIP" install --upgrade -r requirements.txt

# Install dependency to create applications.
mkdir -p elf2tab
rustup install stable
cargo +stable install elf2tab --version 0.10.2 --root elf2tab/
