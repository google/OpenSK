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

SUCCESS=0

# Ensure we are at the project root directory
cd $(readlink -f $(dirname $0))/..

for file in `find . ! -path "./third_party/*" -type f -name '*.py'`
do
  # Output header for our custom matcher on Github workflow
  echo "PYLINT:${file}"
  if ! pylint --rcfile=.pylintrc --score=n "$file"
  then
    SUCCESS=1
  fi
done

exit $SUCCESS
