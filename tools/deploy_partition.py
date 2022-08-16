#!/usr/bin/env python3
# Copyright 2020-2021 Google LLC
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
"""Tool that is part of firmware upgrabability in OpenSK."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import datetime
import hashlib
import os
import struct
from typing import Any
import uuid

import colorama
from tqdm.auto import tqdm

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from fido2 import ctap
from fido2 import hid
from tockloader import tab
from tools.configure import fatal, error, info, get_opensk_devices, get_private_key

OPENSK_VID_PID = (0x1915, 0x521F)
OPENSK_VENDOR_UPGRADE = 0x42
OPENSK_VENDOR_UPGRADE_INFO = 0x43
PAGE_SIZE = 0x1000
KERNEL_SIZE = 0x20000
APP_SIZE = 0x20000
PARTITION_ADDRESS = {
    "nrf52840dk_opensk_a": 0x20000,
    "nrf52840dk_opensk_b": 0x60000,
}
ES256_ALGORITHM = -7
ARCH = "thumbv7em-none-eabi"


def create_metadata(firmware_image: bytes, partition_address: int) -> bytes:
  """Creates the matching metadata for the given firmware.

  The metadata consists of a timestamp, the expected address and a hash of
  the image and the other properties in this metadata.

  Args:
    firmware_image: A byte array of kernel and app, padding to full length.
    partition_address: The address to be written as a metadata property.

  Returns:
    A byte array consisting of 32B hash, 4B timestamp and 4B partition address
    in little endian encoding.
  """
  t = datetime.datetime.utcnow().timestamp()
  timestamp = struct.pack("<I", int(t))
  partition_start = struct.pack("<I", partition_address)
  sha256_hash = hashlib.sha256()
  sha256_hash.update(firmware_image)
  sha256_hash.update(timestamp)
  sha256_hash.update(partition_start)
  checksum = sha256_hash.digest()
  return checksum + timestamp + partition_start


def hash_message(message: bytes) -> bytes:
  """Uses SHA256 to hash a message."""
  sha256_hash = hashlib.sha256()
  sha256_hash.update(message)
  return sha256_hash.digest()


def check_info(partition_address: int, authenticator: Any):
  """Checks if the assumed upgrade info matches the authenticator's."""
  try:
    info("Reading upgrade info...")
    result = authenticator.send_cbor(
        OPENSK_VENDOR_UPGRADE_INFO,
        data={},
    )
    if result[0x01] != partition_address:
      fatal("Identifiers do not match.")
  except ctap.CtapError as ex:
    error(f"Failed to read OpenSK upgrade info (error: {ex}")


def get_kernel(board: str) -> bytes:
  """Reads the kernel binary from file."""
  kernel_file = f"third_party/tock/target/{ARCH}/release/{board}.bin"
  if not os.path.exists(kernel_file):
    fatal(f"File not found: {kernel_file}")
  with open(kernel_file, "rb") as firmware:
    binary = firmware.read()
  return binary


def get_app(board: str) -> bytes:
  """Reads the app binary for the given board from a TAB file."""
  app_tab_path = "target/tab/ctap2.tab"
  if not os.path.exists(app_tab_path):
    fatal(f"File not found: {app_tab_path}")
  app_tab = tab.TAB(app_tab_path)
  if ARCH not in app_tab.get_supported_architectures():
    fatal(f"Architecture not found: {ARCH}")
  app_address = PARTITION_ADDRESS[board] + KERNEL_SIZE
  return app_tab.extract_app(ARCH).get_binary(app_address)


def pad_to(binary: bytes, length: int) -> bytes:
  """Extends the given binary to the new length with a 0xFF padding."""
  if len(binary) > length:
    fatal(f"Binary size {len(binary)} exceeds flash partition {length}.")
  padding = bytes([0xFF] * (length - len(binary)))
  return binary + padding


def generate_firmware_image(board: str) -> bytes:
  """Creates binaries for kernel and app, to generate a full firmware image."""
  kernel = get_kernel(board)
  app = get_app(board)
  return pad_to(kernel, KERNEL_SIZE) + pad_to(app, APP_SIZE)


def load_priv_key(priv_key_file: argparse.FileType) -> Any:
  """Loads the ECDSA private key from the specified file."""
  priv_key = get_private_key(priv_key_file.read())
  if not isinstance(priv_key, ec.EllipticCurvePrivateKey):
    fatal("Private key must be an Elliptic Curve one.")
  if not isinstance(priv_key.curve, ec.SECP256R1):
    fatal("Private key must use Secp256r1 curve.")
  if priv_key.key_size != 256:
    fatal("Private key must be 256 bits long.")
  info("Private key is valid.")
  return priv_key


def sign_firmware(data: bytes, priv_key: Any) -> bytes:
  """Signs the data with the passed key and returns the signature bytes."""
  signature_der = priv_key.sign(data, ec.ECDSA(hashes.SHA256()))
  (r, s) = decode_dss_signature(signature_der)
  return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def main(args):
  colorama.init()

  firmware_image = generate_firmware_image(args.board)
  partition_address = PARTITION_ADDRESS[args.board]
  metadata = create_metadata(firmware_image, partition_address)

  if not args.priv_key:
    fatal("Please pass in a private key file using --private-key.")
  priv_key = load_priv_key(args.priv_key)
  signed_data = firmware_image + metadata[32:40]
  signature = {
      "alg": ES256_ALGORITHM,
      "signature": sign_firmware(signed_data, priv_key)
  }

  for authenticator in tqdm(get_opensk_devices(args.batch)):
    # If the device supports it, wink to show which device we upgrade.
    if authenticator.device.capabilities & hid.CAPABILITY.WINK:
      authenticator.device.wink()
    aaguid = uuid.UUID(bytes=authenticator.get_info().aaguid)
    info(f"Upgrading OpenSK device AAGUID {aaguid} ({authenticator.device}).")

    try:
      check_info(partition_address, authenticator)
      offset = 0
      for offset in range(0, len(firmware_image), PAGE_SIZE):
        page = firmware_image[offset:][:PAGE_SIZE]
        info(f"Writing at offset 0x{offset:08X}...")
        cbor_data = {1: offset, 2: page, 3: hash_message(page)}
        authenticator.send_cbor(
            OPENSK_VENDOR_UPGRADE,
            data=cbor_data,
        )

      info("Writing metadata...")
      cbor_data = {2: metadata, 3: hash_message(metadata), 4: signature}
      authenticator.send_cbor(
          OPENSK_VENDOR_UPGRADE,
          data=cbor_data,
      )
    except ctap.CtapError as ex:
      message = "Failed to upgrade OpenSK"
      if ex.code.value == ctap.CtapError.ERR.INVALID_COMMAND:
        error(f"{message} (unsupported command).")
      elif ex.code.value == ctap.CtapError.ERR.INVALID_PARAMETER:
        error(f"{message} (invalid parameter, maybe a wrong byte array size?).")
      elif ex.code.value == ctap.CtapError.ERR_INTEGRITY_FAILURE:
        error(f"{message} (hashes or signature don't match).")
      elif ex.code.value == 0xF2:  # VENDOR_INTERNAL_ERROR
        error(f"{message} (internal conditions not met).")
      elif ex.code.value == 0xF3:  # VENDOR_HARDWARE_FAILURE
        error(f"{message} (internal hardware error).")
      else:
        error(f"{message} (unexpected error: {ex}")


if __name__ == "__main__":
  # Make sure the current working directory is the right one before running
  os.chdir(os.path.realpath(os.path.dirname(__file__)))
  os.chdir("..")

  parser = argparse.ArgumentParser()
  parser.add_argument(
      "--batch",
      default=False,
      action="store_true",
      help=(
          "When batch processing is used, all plugged OpenSK devices will "
          "be programmed the same way. Otherwise (default) only the first seen "
          "device will be programmed."),
  )
  parser.add_argument(
      "--board",
      type=str,
      choices=["nrf52840dk_opensk_a", "nrf52840dk_opensk_b"],
      dest="board",
      help=("Binary file containing the compiled firmware."),
  )
  parser.add_argument(
      "--private-key",
      type=argparse.FileType("rb"),
      default="crypto_data/opensk_upgrade.key",
      dest="priv_key",
      help=("PEM file for signing the firmware."),
  )
  main(parser.parse_args())
