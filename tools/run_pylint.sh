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

# Ensure we are at the project root directory
cd $(readlink -f $(dirname $0))/..

if [ -f "py_virtual_env/bin/pylint" ]; then
    PYLINT=py_virtual_env/bin/pylint
else
    PYLINT=pylint
fi

"$PYLINT" --score=n `git ls-files --deduplicate --exclude-standard --full-name '*.py'`
