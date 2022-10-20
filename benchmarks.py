#!/usr/bin/env python3
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
# Lint as: python3
"""Script to benchmark CTAP commands using Dilithium Hybrid signatures."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import datetime
from subprocess import DEVNULL, STDOUT, check_call
import sys
from time import sleep
from typing import Any
import uuid

import colorama
from tqdm.auto import tqdm

from fido2 import ctap
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialParameters
from fido2 import hid
from tools.configure import fatal, info, get_opensk_devices

ES256_ALGORITHM = PublicKeyCredentialParameters("public-key", -7)
HYBRID_ALGORITHM = PublicKeyCredentialParameters("public-key", -65537)


def error(message: str):
  tqdm.write(message)


def check_info(authenticator: Any):
  """Checks if the assumed upgrade info matches the authenticator's."""
  try:
    info("Reading info...")
    if HYBRID_ALGORITHM not in authenticator.info.algorithms:
      fatal("The device does not support hybrid signatures.")
  except ctap.CtapError as ex:
    error(f"Failed to read OpenSK info (error: {ex}")


def f_args(*params):
  """Constructs a dict from a list of arguments for sending a CBOR command.
    None elements will be omitted.
    :param params: Arguments, in order, to add to the command.
    :return: The input parameters as a dict.
    """
  return dict((i, v) for i, v in enumerate(params, 1) if v is not None)


def compute_stats(elapsed):
  n = len(elapsed)
  mean = sum(elapsed) / n
  variance = sum((x - mean)**2 for x in elapsed) / n
  std_dev = variance**0.5
  return (mean, std_dev)


def get_authenticator():
  devices = None
  while not devices:
    try:
      devices = get_opensk_devices(False)
    except Exception as e:  # pylint: disable=broad-except
      error(str(e))
      check_call(["nrfjprog", "--reset", "--family", "NRF52"],
                 stdout=DEVNULL,
                 stderr=STDOUT)
      sleep(0.1)
  return devices[0]


def main(args):
  colorama.init()

  authenticator = get_authenticator()
  # If the device supports it, wink to show which device we use.
  if authenticator.device.capabilities & hid.CAPABILITY.WINK:
    authenticator.device.wink()
  aaguid = uuid.UUID(bytes=authenticator.get_info().aaguid)
  check_info(authenticator)
  info(f"Testing OpenSK device AAGUID {aaguid} ({authenticator.device}).")

  make_durations = []
  get_durations = []

  for _ in tqdm(range(args.runs), file=sys.stdout):
    authenticator = get_authenticator()
    try:
      start = datetime.datetime.now()
      result = authenticator.make_credential(
          client_data_hash=bytes(32),
          rp=PublicKeyCredentialRpEntity(id="example.com", name="Example"),
          user=PublicKeyCredentialUserEntity(id=b"diana", name="Diana"),
          key_params=[HYBRID_ALGORITHM],
      )
      end = datetime.datetime.now()
      make_delta = (end - start).total_seconds() * 1000.0
      make_durations.append(make_delta)

      credential_data = result.auth_data.credential_data
      credential_id_length = 256 * credential_data[16] + credential_data[17]
      credential_id = credential_data[18:18 + credential_id_length]
      allow_list = [{"type": "public-key", "id": credential_id}]

      start = datetime.datetime.now()
      _ = authenticator.get_assertion(
          rp_id="example.com",
          client_data_hash=bytes(32),
          allow_list=allow_list,
      )
      end = datetime.datetime.now()
      get_delta = (end - start).total_seconds() * 1000.0
      get_durations.append(get_delta)

      with open("make_durations.txt", "a", encoding="utf-8") as file_make:
        file_make.write(str(make_delta) + ",\n")
      with open("get_durations.txt", "a", encoding="utf-8") as file_get:
        file_get.write(str(get_delta) + ",\n")

    except ctap.CtapError as ex:
      message = "Failed to make a hybrid signature with OpenSK"
      if ex.code.value == ctap.CtapError.ERR.INVALID_COMMAND:
        error(f"{message} (unsupported command).")
      elif ex.code.value == ctap.CtapError.ERR.INVALID_PARAMETER:
        error(f"{message} (invalid parameter, maybe a wrong byte array size?).")
      elif ex.code.value == 0xF2:  # VENDOR_INTERNAL_ERROR
        error(f"{message} (internal conditions not met).")
      elif ex.code.value == 0xF3:  # VENDOR_HARDWARE_FAILURE
        error(f"{message} (internal hardware error).")
      else:
        error(f"{message} (unexpected error: {ex})")
    except Exception as e:  # pylint: disable=broad-except
      error(str(e))

  info(f"Successful operations: {len(make_durations)} and {len(get_durations)}")
  info("\nMake Credential benchmark:")
  (mean, std_dev) = compute_stats(make_durations)
  info(f"Average: {mean} ms/iter (standard deviation: {std_dev} ms/iter)")
  info("\nGet Assertion benchmark:")
  (mean, std_dev) = compute_stats(get_durations)
  info(f"Average: {mean} ms/iter (standard deviation: {std_dev} ms/iter)")


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "--runs",
      type=int,
      default=1000,
      help=("How many iterations to use."),
  )
  main(parser.parse_args())
