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
# Result file is $3

WARNING="Note: numbers above are a result of guesswork. They are not 100% correct and never will be."

NEW_SIZE=$(cat "$1" | sed -nr 's/.*100.0% (.*)KiB .text.*/\1/p')
OLD_SIZE=$(cat "$2" | sed -nr 's/.*100.0% (.*)KiB .text.*/\1/p')
echo "Binary size:
\`\`\`diff
- $OLD_SIZE kiB
+ $NEW_SIZE kiB
\`\`\`" > "$3"

echo "<details>
<summary>Output for cargo bloat</summary>
<br>
<pre>" >> "$3"

echo "<h3>Including PR</h3>" >> "$3"
cat "$1" | sed "s/$WARNING//" >> "$3"
echo "<h3>Base branch</h3>" >> "$3"
cat "$2" | sed "s/$WARNING//" >> "$3"

echo "
</pre>
</details>" >> "$3"
