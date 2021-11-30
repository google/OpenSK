#!/usr/bin/env bash
# Copyright 2020 Google LLC
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
shopt -s nullglob

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

# Copy additional boards to the kernel.
echo -n '[-] Copying additional boards to Tock... '
cp -r boards/* third_party/tock/boards
echo $done_text

for module in tock libtock-rs; do
  # Apply patches to the submodule. Do that in a sub-shell.
  (
    cd third_party/"${module}"/ && \
      for p in ../../patches/"${module}"/*.patch
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
done
