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

echo "$(tput bold)This script will restore the repository to a clean state$(tput sgr0)"
echo "$(tput bold)Any pending change will be lost.$(tput sgr0)"
echo ""

accept=''
while
  case "$accept" in
    [Yy])
      # Start echoeing the commands to the screen
      set -x
      # Reset the submodules
      git submodule foreach 'git reset --hard && git clean -fxd'
      # Reset also the main repository
      git reset --hard && git clean -fxd --exclude elf2tab

      set +x
      echo "DONE."
      # And break the loop
      false
    ;;

    [Nn])
      echo "Nothing was done. Repository was left untouched."
      # Don't do anything but break the while loop to exit
      false
    ;;

    *)
      # Continue looping
      true
    ;;
  esac
do
    echo "$(tput bold)Are you sure you want to continue? [y/n]$(tput sgr0)"
    read -s -n 1 accept
done
