#!/bin/bash
# Copyright 2022 Google LLC
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

cd "$(dirname "$0")"

# New output file is $1
# Old output file is $2
TMP=comment.md
WARNING="Note: numbers above are a result of guesswork. They are not 100% correct and never will be."
NEW_SIZE=$(cat "$1" | sed -nr 's/.*100.0% (.*)KiB .text.*/\1/p')
OLD_SIZE=$(cat "$2" | sed -nr 's/.*100.0% (.*)KiB .text.*/\1/p')

echo "
OLD $OLD_SIZE kiB
NEW $NEW_SIZE kiB" > "$TMP"

echo "
Output of cargo bloat
======================
" >> "$TMP"

echo "Including PR" >> "$TMP"
cat "$1" >> "$TMP"
echo "Base branch" >> "$TMP"
cat "$2" >> "$TMP"

COMMENT="$(cat $TMP | sed "s/$WARNING//g" | sed 's/%/%25/g' | sed -z 's/\n/%0A/g')"
# No output for equality is intentional.
if (( $(echo "$NEW_SIZE > $OLD_SIZE" | bc -l) )); then
  echo "::warning file=.github/workflows/cargo_bloat.yml,title=Binary size::$COMMENT"
fi
if (( $(echo "$NEW_SIZE < $OLD_SIZE" | bc -l) )); then
  echo "::notice file=.github/workflows/cargo_bloat.yml,title=Binary size::$COMMENT"
fi
