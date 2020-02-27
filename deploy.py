#!/usr/bin/env python3
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
# Lint as: python3

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import copy
import os
import shutil
import subprocess
import sys

import colorama
from tockloader.exceptions import TockLoaderException
from tockloader import tab, tbfh, tockloader

# This structure allows us in the future to also support out-of-tree boards.
SUPPORTED_BOARDS = {
    "nrf52840_dk": "third_party/tock/boards/nordic/nrf52840dk",
    "nrf52840_dongle": "third_party/tock/boards/nordic/nrf52840_dongle"
}

# The STACK_SIZE value below must match the one used in the linker script
# used by the board.
# e.g. for Nordic nRF52840 boards the file is `nrf52840dk_layout.ld`.
STACK_SIZE = 0x4000

# The following value must match the one used in the file
# `src/entry_point.rs`
APP_HEAP_SIZE = 90000


def get_supported_boards():
  boards = []
  for name, root in SUPPORTED_BOARDS.items():
    if all((os.path.exists(os.path.join(root, "Cargo.toml")),
            os.path.exists(os.path.join(root, "Makefile")))):
      boards.append(name)
  return tuple(set(boards))


def fatal(msg):
  print("{style_begin}fatal:{style_end} {message}".format(
      style_begin=colorama.Fore.RED + colorama.Style.BRIGHT,
      style_end=colorama.Style.RESET_ALL,
      message=msg))
  sys.exit(1)


def error(msg):
  print("{style_begin}error:{style_end} {message}".format(
      style_begin=colorama.Fore.RED,
      style_end=colorama.Style.RESET_ALL,
      message=msg))


def info(msg):
  print("{style_begin}info:{style_end} {message}".format(
      style_begin=colorama.Fore.GREEN + colorama.Style.BRIGHT,
      style_end=colorama.Style.RESET_ALL,
      message=msg))


class RemoveConstAction(argparse.Action):

  #pylint: disable=W0622
  def __init__(self,
               option_strings,
               dest,
               const,
               default=None,
               required=False,
               help=None,
               metavar=None):
    super(RemoveConstAction, self).__init__(
        option_strings=option_strings,
        dest=dest,
        nargs=0,
        const=const,
        default=default,
        required=required,
        help=help,
        metavar=metavar)

  def __call__(self, parser, namespace, values, option_string=None):
    # Code is simply a modified version of the AppendConstAction from argparse
    # https://github.com/python/cpython/blob/master/Lib/argparse.py#L138-L147
    # https://github.com/python/cpython/blob/master/Lib/argparse.py#L1028-L1052
    items = getattr(namespace, self.dest, [])
    if isinstance(items, list):
      items = items[:]
    else:
      items = copy.copy(items)
    if self.const in items:
      items.remove(self.const)
    setattr(namespace, self.dest, items)


class OpenSKInstaller:

  def __init__(self, args):
    colorama.init()
    self.args = args
    # Where all the TAB files should go
    self.tab_folder = os.path.join("target", "tab")
    # This is the filename that elf2tab command expects in order
    # to create a working TAB file.
    self.target_elf_filename = os.path.join(self.tab_folder, "cortex-m4.elf")
    self.tockloader_default_args = argparse.Namespace(
        arch="cortex-m4",
        board=getattr(self.args, "board", "nrf52840"),
        debug=False,
        force=False,
        jlink=True,
        jlink_device="nrf52840_xxaa",
        jlink_if="swd",
        jlink_speed=1200,
        jtag=False,
        no_bootloader_entry=False,
        page_size=4096,
        port=None,
    )

  def checked_command_output(self, cmd):
    cmd_output = ""
    try:
      cmd_output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
      fatal("Failed to execute {}: {}".format(cmd[0], str(e)))
      # Unreachable because fatal() will exit
    return cmd_output.decode()

  def update_rustc_if_needed(self):
    target_toolchain_fullstring = "stable"
    with open("rust-toolchain", "r") as f:
      target_toolchain_fullstring = f.readline().strip()
    target_toolchain = target_toolchain_fullstring.split("-", maxsplit=1)
    if len(target_toolchain) == 1:
      # If we target the stable version of rust, we won't have a date
      # associated to the version and split will only return 1 item.
      # To avoid failing later when accessing the date, we insert an
      # empty value.
      target_toolchain.append('')
    current_version = self.checked_command_output(["rustc", "--version"])
    if not all((target_toolchain[0] in current_version,
                target_toolchain[1] in current_version)):
      info("Updating rust toolchain to {}".format("-".join(target_toolchain)))
      # Need to update
      self.checked_command_output(
          ["rustup", "install", target_toolchain_fullstring])
      self.checked_command_output(
          ["rustup", "target", "add", "thumbv7em-none-eabi"])
    info("Rust toolchain up-to-date")

  def build_and_install_tockos(self):
    self.checked_command_output(
        ["make", "-C", SUPPORTED_BOARDS[self.args.board], "flash"])

  def build_and_install_example(self):
    assert self.args.application
    self.checked_command_output([
        "cargo", "build", "--release", "--target=thumbv7em-none-eabi",
        "--features={}".format(",".join(self.args.features)), "--example",
        self.args.application
    ])
    self.install_elf_file(
        os.path.join("target/thumbv7em-none-eabi/release/examples",
                     self.args.application))

  def build_and_install_opensk(self):
    assert self.args.application
    info("Building OpenSK application")
    self.checked_command_output([
        "cargo",
        "build",
        "--release",
        "--target=thumbv7em-none-eabi",
        "--features={}".format(",".join(self.args.features)),
    ])
    self.install_elf_file(
        os.path.join("target/thumbv7em-none-eabi/release",
                     self.args.application))

  def generate_crypto_materials(self, force_regenerate):
    has_error = subprocess.call([
        os.path.join("tools", "gen_key_materials.sh"),
        "Y" if force_regenerate else "N",
    ])
    if has_error:
      error(("Something went wrong while trying to generate ECC "
             "key and/or certificate for OpenSK"))

  def install_elf_file(self, elf_path):
    assert self.args.application
    package_parameter = "-n"
    elf2tab_ver = self.checked_command_output(["elf2tab", "--version"]).split(
        ' ', maxsplit=1)[1]
    # Starting from v0.5.0-dev the parameter changed.
    # Current pyblished crate is 0.4.0 but we don't want developers
    # running the HEAD from github to be stuck
    if "0.5.0-dev" in elf2tab_ver:
      package_parameter = "--package-name"
    os.makedirs(self.tab_folder, exist_ok=True)
    tab_filename = os.path.join(self.tab_folder,
                                "{}.tab".format(self.args.application))
    shutil.copyfile(elf_path, self.target_elf_filename)
    self.checked_command_output([
        "elf2tab", package_parameter, self.args.application, "-o", tab_filename,
        self.target_elf_filename, "--stack={}".format(STACK_SIZE),
        "--app-heap={}".format(APP_HEAP_SIZE), "--kernel-heap=1024",
        "--protected-region-size=64"
    ])
    self.install_padding()
    info("Installing Tock application {}".format(self.args.application))
    args = copy.copy(self.tockloader_default_args)
    setattr(args, "app_address", 0x40000)
    setattr(args, "erase", self.args.clear_apps)
    setattr(args, "make", False)
    setattr(args, "no_replace", False)
    tock = tockloader.TockLoader(args)
    tock.open(args)
    tabs = [tab.TAB(tab_filename)]
    try:
      tock.install(tabs, replace="yes", erase=args.erase)
    except TockLoaderException as e:
      fatal("Couldn't install Tock application {}: {}".format(
          self.args.application, str(e)))

  def install_padding(self):
    fake_header = tbfh.TBFHeader("")
    fake_header.version = 2
    fake_header.fields["header_size"] = 0x10
    fake_header.fields["total_size"] = 0x10000
    fake_header.fields["flags"] = 0
    padding = fake_header.get_binary()
    info("Flashing padding application")
    args = copy.copy(self.tockloader_default_args)
    setattr(args, "address", 0x30000)
    tock = tockloader.TockLoader(args)
    tock.open(args)
    try:
      tock.flash_binary(padding, args.address)
    except TockLoaderException as e:
      fatal("Couldn't install padding: {}".format(str(e)))

  def clear_apps(self):
    args = copy.copy(self.tockloader_default_args)
    setattr(args, "app_address", 0x40000)
    info("Erasing all installed applications")
    tock = tockloader.TockLoader(args)
    tock.open(args)
    try:
      tock.erase_apps(False)
    except TockLoaderException as e:
      # Erasing apps is not critical
      info(("A non-critical error occured while erasing "
            "apps: {}".format(str(e))))

  def verify_flashed_app(self, expected_app):
    args = copy.copy(self.tockloader_default_args)
    tock = tockloader.TockLoader(args)
    app_found = False
    with tock._start_communication_with_board():
      apps = [app.name for app in tock._extract_all_app_headers()]
      app_found = expected_app in apps
    return app_found

  def run(self):
    if self.args.action is None:
      # Nothing to do
      return 0

    self.update_rustc_if_needed()

    if self.args.action == "os":
      info("Installing Tock on board {}".format(self.args.board))
      self.build_and_install_tockos()
      return 0

    if self.args.action == "app":
      if self.args.application is None:
        fatal("Unspecified application")
      if self.args.clear_apps:
        self.clear_apps()
      if self.args.application == "ctap2":
        self.generate_crypto_materials(self.args.regenerate_keys)
        self.build_and_install_opensk()
      else:
        self.build_and_install_example()
      if self.verify_flashed_app(self.args.application):
        info("You're all set!")
        return 0
      error(("It seems that something went wrong. "
             "App/example not found on your board."))
      return 1
    return 0


def main(args):
  # Make sure the current working directory is the right one before running
  os.chdir(os.path.realpath(os.path.dirname(__file__)))
  # Check for pre-requisite executable files.
  if not shutil.which("JLinkExe"):
    fatal(("Couldn't find JLinkExe binary. Make sure Segger JLink tools "
           "are installed and correctly set up."))

  OpenSKInstaller(args).run()


if __name__ == '__main__':
  shared_parser = argparse.ArgumentParser(add_help=False)
  shared_parser.add_argument(
      "--dont-clear-apps",
      action="store_false",
      default=True,
      dest="clear_apps",
      help=("When installing an application, previously installed "
            "applications won't be erased from the board."),
  )

  main_parser = argparse.ArgumentParser()
  commands = main_parser.add_subparsers(
      dest="action",
      help=("Indicates which part of the firmware should be compiled and "
            "flashed to the connected board."))

  os_commands = commands.add_parser(
      "os",
      parents=[shared_parser],
      help=("Compiles and installs Tock OS. The target board must be "
            "specified by setting the --board argument."),
  )
  os_commands.add_argument(
      "--board",
      metavar="BOARD_NAME",
      dest="board",
      choices=get_supported_boards(),
      help="Indicates which board Tock OS will be compiled for.",
      required=True)

  app_commands = commands.add_parser(
      "app",
      parents=[shared_parser],
      help="compiles and installs an application.")
  app_commands.add_argument(
      "--panic-console",
      action="append_const",
      const="panic_console",
      dest="features",
      help=("In case of application panic, the console will be used to "
            "output messages before starting blinking the LEDs on the "
            "board."),
  )
  app_commands.add_argument(
      "--no-u2f",
      action=RemoveConstAction,
      const="with_ctap1",
      dest="features",
      help=("Compiles the OpenSK application without backward compatible "
            "support for U2F/CTAP1 protocol."),
  )
  app_commands.add_argument(
      "--regen-keys",
      action="store_true",
      default=False,
      dest="regenerate_keys",
      help=("Forces the generation of files (certificates and private keys) "
            "under the crypto_data/ directory. "
            "This is useful to allow flashing multiple OpenSK authenticators "
            "in a row without them being considered clones."),
  )
  app_commands.add_argument(
      "--debug",
      action="append_const",
      const="debug_ctap",
      dest="features",
      help=("Compiles and installs the  OpenSK application in debug mode "
            "(i.e. more debug messages will be sent over the console port "
            "such as hexdumps of packets)."),
  )
  apps_group = app_commands.add_mutually_exclusive_group()
  apps_group.add_argument(
      "--opensk",
      dest="application",
      action="store_const",
      const="ctap2",
      help="Compiles and installs the OpenSK application.")
  apps_group.add_argument(
      "--crypto_bench",
      dest="application",
      action="store_const",
      const="crypto_bench",
      help=("Compiles and installs the crypto_bench example that tests "
            "the performance of the cryptographic algorithms on the board."))

  app_commands.set_defaults(features=["with_ctap1"])

  main(main_parser.parse_args())
