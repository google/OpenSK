#!/bin/bash
# Copyright 2021 Google LLC
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

# Creates a signature key and configures the public key.
# The device will not be locked down for testing purposes.
# Generates the binary and upgrades OpenSK.
# To be run from the OpenSK base path.

set -e

BOARD="$1"

./deploy.py --board=$BOARD --opensk --programmer=none
python3 -m tools.deploy_partition --board=$BOARD
if nrfjprog --reset --family NRF52 ; then
  echo "Upgrade finished!"
else
  echo "Please replug OpenSK to reboot"
fi
