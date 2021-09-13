#!/usr/bin/env python3
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
# Lint as: python3

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import getpass
import datetime
import sys
import uuid

import colorama
from tqdm.auto import tqdm

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from fido2 import ctap
from fido2 import ctap2
from fido2 import hid

OPENSK_VID_PID = (0x1915, 0x521F)
OPENSK_VENDOR_CONFIGURE = 0x40


def fatal(msg):
  tqdm.write("{style_begin}fatal:{style_end} {message}".format(
      style_begin=colorama.Fore.RED + colorama.Style.BRIGHT,
      style_end=colorama.Style.RESET_ALL,
      message=msg))
  sys.exit(1)


def error(msg):
  tqdm.write("{style_begin}error:{style_end} {message}".format(
      style_begin=colorama.Fore.RED,
      style_end=colorama.Style.RESET_ALL,
      message=msg))


def info(msg):
  tqdm.write("{style_begin}info:{style_end} {message}".format(
      style_begin=colorama.Fore.GREEN + colorama.Style.BRIGHT,
      style_end=colorama.Style.RESET_ALL,
      message=msg))


def get_opensk_devices(batch_mode):
  devices = []
  for dev in hid.CtapHidDevice.list_devices():
    if (dev.descriptor.vid, dev.descriptor.pid) == OPENSK_VID_PID:
      if dev.capabilities & hid.CAPABILITY.CBOR:
        if batch_mode:
          devices.append(ctap2.CTAP2(dev))
        else:
          return [ctap2.CTAP2(dev)]
  return devices


def get_private_key(data, password=None):
  # First we try without password.
  try:
    return serialization.load_pem_private_key(data, password=None)
  except TypeError:
    # Maybe we need a password then.
    if sys.stdin.isatty():
      password = getpass.getpass(prompt="Private key password: ")
    else:
      password = sys.stdin.readline().rstrip()
    return get_private_key(data, password=password.encode(sys.stdin.encoding))


def main(args):
  colorama.init()
  # We need either both the certificate and the key or none
  if bool(args.priv_key) ^ bool(args.certificate):
    fatal("Certificate and private key must be set together or both omitted.")

  cbor_data = {1: args.lock}

  if args.priv_key:
    cbor_data[1] = args.lock
    priv_key = get_private_key(args.priv_key.read())
    if not isinstance(priv_key, ec.EllipticCurvePrivateKey):
      fatal("Private key must be an Elliptic Curve one.")
    if not isinstance(priv_key.curve, ec.SECP256R1):
      fatal("Private key must use Secp256r1 curve.")
    if priv_key.key_size != 256:
      fatal("Private key must be 256 bits long.")
    info("Private key is valid.")

    cert = x509.load_pem_x509_certificate(args.certificate.read())
    # Some sanity/validity checks
    now = datetime.datetime.utcnow()
    if cert.not_valid_before > now:
      fatal("Certificate validity starts in the future.")
    if cert.not_valid_after <= now:
      fatal("Certificate expired.")
    pub_key = cert.public_key()
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
      fatal("Certificate public key must be an Elliptic Curve one.")
    if not isinstance(pub_key.curve, ec.SECP256R1):
      fatal("Certificate public key must use Secp256r1 curve.")
    if pub_key.key_size != 256:
      fatal("Certificate public key must be 256 bits long.")
    if pub_key.public_numbers() != priv_key.public_key().public_numbers():
      fatal("Certificate public doesn't match with the private key.")
    info("Certificate is valid.")

    cbor_data[2] = {
        1:
            cert.public_bytes(serialization.Encoding.DER),
        2:
            priv_key.private_numbers().private_value.to_bytes(
                length=32, byteorder='big', signed=False)
    }

  for authenticator in tqdm(get_opensk_devices(args.batch)):
    # If the device supports it, wink to show which device
    # we're going to program.
    if authenticator.device.capabilities & hid.CAPABILITY.WINK:
      authenticator.device.wink()
    aaguid = uuid.UUID(bytes=authenticator.get_info().aaguid)
    info("Programming OpenSK device AAGUID {} ({}).".format(
        aaguid, authenticator.device))
    info("Please touch the device to confirm...")
    try:
      result = authenticator.send_cbor(
          OPENSK_VENDOR_CONFIGURE,
          data=cbor_data,
      )
      info("Certificate: {}".format("Present" if result[1] else "Missing"))
      info("Private Key: {}".format("Present" if result[2] else "Missing"))
      if args.lock:
        info("Device is now locked down!")
    except ctap.CtapError as ex:
      if ex.code.value == ctap.CtapError.ERR.INVALID_COMMAND:
        error("Failed to configure OpenSK (unsupported command).")
      elif ex.code.value == 0xF2:  # VENDOR_INTERNAL_ERROR
        error(("Failed to configure OpenSK (lockdown conditions not met "
               "or hardware error)."))
      elif ex.code.value == ctap.CtapError.ERR.INVALID_PARAMETER:
        error(
            ("Failed to configure OpenSK (device is partially programmed but "
             "the given cert/key don't match the ones currently programmed)."))
      else:
        error("Failed to configure OpenSK (unknown error: {}".format(ex))


if __name__ == "__main__":
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
      "--certificate",
      type=argparse.FileType("rb"),
      default=None,
      metavar="PEM_FILE",
      dest="certificate",
      help=("PEM file containing the certificate to inject into "
            "the OpenSK authenticator."),
  )
  parser.add_argument(
      "--private-key",
      type=argparse.FileType("rb"),
      default=None,
      metavar="PEM_FILE",
      dest="priv_key",
      help=("PEM file containing the private key associated "
            "with the certificate."),
  )
  parser.add_argument(
      "--lock-device",
      default=False,
      action="store_true",
      dest="lock",
      help=("Locks the device (i.e. bootloader and JTAG access). "
            "This command can fail if the certificate or the private key "
            "haven't been both programmed yet."),
  )
  main(parser.parse_args())
