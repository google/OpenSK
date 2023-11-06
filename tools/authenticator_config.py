# Copyright 2023 Google LLC
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
# Lint as: python3
"""Tool that sends a config command to OpenSK."""

from __future__ import absolute_import, division, print_function

import argparse
import colorama
from fido2 import hid
from fido2.ctap2 import Config
import uuid

from tools.configure import fatal, get_opensk_devices, info


def main(args):
  colorama.init()

  devices = get_opensk_devices(False)
  if not devices:
    fatal("No devices found.")

  for authenticator in devices:
    if authenticator.device.capabilities & hid.CAPABILITY.WINK:
      authenticator.device.wink()
    aaguid = uuid.UUID(bytes=authenticator.get_info().aaguid)
    info(f"Config of device AAGUID {aaguid} ({authenticator.device}).")

    config = Config(authenticator)
    if args.ep:
      info("Enable EP...")
      config.enable_enterprise_attestation()
    if args.always_uv:
      info("Toggle AlwaysUv...")
      config.toggle_always_uv()


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--ep", action=argparse.BooleanOptionalAction)
  parser.add_argument("--always-uv", action=argparse.BooleanOptionalAction)
  main(parser.parse_args())
