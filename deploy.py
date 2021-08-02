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
# pylint: disable=C0111

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import collections
import copy
import os
import shutil
import subprocess
import sys

import colorama
from six.moves import input
import tockloader
from tockloader import tab
from tockloader import tbfh
from tockloader import tockloader as loader
from tockloader.exceptions import TockLoaderException

PROGRAMMERS = frozenset(("jlink", "openocd", "pyocd", "nordicdfu", "none"))

# This structure allows us to support out-of-tree boards as well as (in the
# future) more achitectures.
OpenSKBoard = collections.namedtuple(
    "OpenSKBoard",
    [
        # Location of the Tock board (where the Makefile file is)
        "path",
        # Target architecture (e.g. thumbv7em-none-eabi)
        "arch",
        # Size of 1 page of flash memory
        "page_size",
        # Flash address at which the kernel will be written
        "kernel_address",
        # Set to None is padding is not required for the board.
        # This creates a fake Tock OS application that starts at the
        # address specified by this parameter (must match the `prog` value
        # specified on the board's `layout.ld` file) and will end at
        # `app_address`.
        "padding_address",
        # Linker script to produce a working app for this board
        "app_ldscript",
        # Flash address at which the app should be written
        "app_address",
        # Flash address of the storage
        "storage_address",
        # Size of the storage
        "storage_size",
        # Target name for flashing the board using pyOCD
        "pyocd_target",
        # The cfg file in OpenOCD board folder
        "openocd_board",
        # Options to tell Tockloader how to work with OpenOCD
        # Default: []
        "openocd_options",
        # Dictionnary specifying custom commands for OpenOCD
        # Default is an empty dict
        # Valid keys are: program, read, erase
        "openocd_commands",
        # Interface to use with JLink (e.g. swd, jtag, etc.)
        "jlink_if",
        # Device name as supported by JLinkExe
        "jlink_device",
        # Whether Nordic DFU flashing method is supported
        "nordic_dfu",
    ])

SUPPORTED_BOARDS = {
    "nrf52840dk":
        OpenSKBoard(
            path="third_party/tock/boards/nordic/nrf52840dk",
            arch="thumbv7em-none-eabi",
            page_size=4096,
            kernel_address=0,
            padding_address=0x30000,
            app_ldscript="nrf52840_layout.ld",
            app_address=0x40000,
            storage_address=0xC0000,
            storage_size=0x40000,
            pyocd_target="nrf52840",
            openocd_board="nordic_nrf52840_dongle.cfg",
            openocd_options=[],
            openocd_commands={},
            jlink_if="swd",
            jlink_device="nrf52840_xxaa",
            nordic_dfu=False,
        ),
    "nrf52840_dongle":
        OpenSKBoard(
            path="third_party/tock/boards/nordic/nrf52840_dongle",
            arch="thumbv7em-none-eabi",
            page_size=4096,
            kernel_address=0,
            padding_address=0x30000,
            app_ldscript="nrf52840_layout.ld",
            app_address=0x40000,
            storage_address=0xC0000,
            storage_size=0x40000,
            pyocd_target="nrf52840",
            openocd_board="nordic_nrf52840_dongle.cfg",
            openocd_options=[],
            openocd_commands={},
            jlink_if="swd",
            jlink_device="nrf52840_xxaa",
            nordic_dfu=False,
        ),
    "nrf52840_dongle_dfu":
        OpenSKBoard(
            path="third_party/tock/boards/nordic/nrf52840_dongle_dfu",
            arch="thumbv7em-none-eabi",
            page_size=4096,
            kernel_address=0x1000,
            padding_address=0x30000,
            app_ldscript="nrf52840_layout.ld",
            app_address=0x40000,
            storage_address=0xC0000,
            storage_size=0x40000,
            pyocd_target="nrf52840",
            openocd_board="nordic_nrf52840_dongle.cfg",
            openocd_options=[],
            openocd_commands={},
            jlink_if="swd",
            jlink_device="nrf52840_xxaa",
            nordic_dfu=True,
        ),
    "nrf52840_mdk_dfu":
        OpenSKBoard(
            path="third_party/tock/boards/nordic/nrf52840_mdk_dfu",
            arch="thumbv7em-none-eabi",
            page_size=4096,
            kernel_address=0x1000,
            padding_address=0x30000,
            app_ldscript="nrf52840_layout.ld",
            app_address=0x40000,
            storage_address=0xC0000,
            storage_size=0x40000,
            pyocd_target="nrf52840",
            openocd_board="nordic_nrf52840_dongle.cfg",
            openocd_options=[],
            openocd_commands={},
            jlink_if="swd",
            jlink_device="nrf52840_xxaa",
            nordic_dfu=True,
        ),
}

# The STACK_SIZE value below must match the one used in the linker script
# used by the board.
# e.g. for Nordic nRF52840 boards the file is `nrf52840_layout.ld`.
STACK_SIZE = 0x4000

# The following value must match the one used in the file
# `src/entry_point.rs`
APP_HEAP_SIZE = 90000


def get_supported_boards():
  boards = []
  for name, props in SUPPORTED_BOARDS.items():
    if all((os.path.exists(os.path.join(props.path, "Cargo.toml")),
            (props.app_ldscript and os.path.exists(props.app_ldscript)))):
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


def assert_mandatory_binary(binary):
  if not shutil.which(binary):
    fatal(("Couldn't find {} binary. Make sure it is installed and "
           "that your PATH is set correctly.").format(binary))


def assert_python_library(module):
  try:
    __import__(module)
  except ModuleNotFoundError:
    fatal(("Couldn't load python3 module {name}. "
           "Try to run: pip3 install {name}").format(name=module))


class RemoveConstAction(argparse.Action):

  # pylint: disable=redefined-builtin
  def __init__(self,
               option_strings,
               dest,
               const,
               default=None,
               required=False,
               help=None,
               metavar=None):
    super().__init__(
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
    if items is None:
      items = []
    if isinstance(items, list):
      items = items[:]
    else:
      items = copy.copy(items)
    if self.const in items:
      items.remove(self.const)
    setattr(namespace, self.dest, items)


class OpenSKInstaller:

  def __init__(self, args):
    self.args = args
    # Where all the TAB files should go
    self.tab_folder = os.path.join("target", "tab")
    board = SUPPORTED_BOARDS[self.args.board]
    self.tockloader_default_args = argparse.Namespace(
        arch=board.arch,
        board=self.args.board,
        bundle_apps=False,
        debug=False,
        force=False,
        jlink_cmd="JLinkExe",
        jlink=self.args.programmer == "jlink",
        jlink_device=board.jlink_device,
        jlink_if=board.jlink_if,
        jlink_speed=1200,
        openocd=self.args.programmer == "openocd",
        openocd_board=board.openocd_board,
        openocd_cmd="openocd",
        openocd_commands=copy.copy(board.openocd_commands),
        openocd_options=copy.copy(board.openocd_options),
        jtag=False,
        no_bootloader_entry=False,
        page_size=board.page_size,
        port=None,
    )

  def checked_command(self, cmd, env=None, cwd=None):
    stdout = None if self.args.verbose_build else subprocess.DEVNULL
    try:
      subprocess.run(
          cmd, stdout=stdout, timeout=None, check=True, env=env, cwd=cwd)
    except subprocess.CalledProcessError as e:
      fatal("Failed to execute {}: {}".format(cmd[0], str(e)))

  def checked_command_output(self, cmd, env=None, cwd=None):
    cmd_output = ""
    try:
      cmd_output = subprocess.run(
          cmd,
          stdout=subprocess.PIPE,
          timeout=None,
          check=True,
          env=env,
          cwd=cwd).stdout
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
      target_toolchain.append("")
    current_version = self.checked_command_output(["rustc", "--version"])
    if not (target_toolchain[0] in current_version and
            target_toolchain[1] in current_version):
      info("Updating rust toolchain to {}".format("-".join(target_toolchain)))
      # Need to update
      rustup_install = ["rustup"]
      if self.args.verbose_build:
        rustup_install.append("--verbose")
      rustup_install.extend(["install", target_toolchain_fullstring])
      self.checked_command(rustup_install)

    rustup_target = ["rustup"]
    if self.args.verbose_build:
      rustup_target.append("--verbose")
    rustup_target.extend(
        ["target", "add", SUPPORTED_BOARDS[self.args.board].arch])
    self.checked_command(rustup_target)
    info("Rust toolchain up-to-date")

  def build_tockos(self):
    info("Building Tock OS for board {}".format(self.args.board))
    props = SUPPORTED_BOARDS[self.args.board]
    out_directory = os.path.join("third_party", "tock", "target", props.arch,
                                 "release")
    os.makedirs(out_directory, exist_ok=True)

    env = os.environ.copy()
    if self.args.verbose_build:
      env["V"] = "1"
    self.checked_command(["make"], cwd=props.path, env=env)

  def build_example(self):
    info("Building example {}".format(self.args.application))
    self._build_app_or_example(is_example=True)

  def build_opensk(self):
    info("Building OpenSK application")
    self._build_app_or_example(is_example=False)

  def _build_app_or_example(self, is_example):
    assert self.args.application
    # Ideally we would build a TAB file for all boards at once but depending on
    # the chip on the board, the link script could be totally different.
    # And elf2tab doesn't seem to let us set the boards a TAB file has been
    # created for. So at the moment we only build for the selected board.
    props = SUPPORTED_BOARDS[self.args.board]
    rust_flags = [
        "-C",
        "link-arg=-T{}".format(props.app_ldscript),
        "-C",
        "relocation-model=static",
        "-D",
        "warnings",
        "--remap-path-prefix={}=".format(os.getcwd()),
    ]
    env = os.environ.copy()
    env["RUSTFLAGS"] = " ".join(rust_flags)
    env["APP_HEAP_SIZE"] = str(APP_HEAP_SIZE)

    command = [
        "cargo", "build", "--release", "--target={}".format(props.arch),
        "--features={}".format(",".join(self.args.features))
    ]
    if is_example:
      command.extend(["--example", self.args.application])
    if self.args.verbose_build:
      command.append("--verbose")
    self.checked_command(command, env=env)
    app_path = os.path.join("target", props.arch, "release")
    if is_example:
      app_path = os.path.join(app_path, "examples")
    app_path = os.path.join(app_path, self.args.application)
    # Create a TAB file
    self.create_tab_file({props.arch: app_path})

  def generate_crypto_materials(self, force_regenerate):
    has_error = subprocess.call([
        os.path.join("tools", "gen_key_materials.sh"),
        "Y" if force_regenerate else "N",
    ])
    if has_error:
      error(("Something went wrong while trying to generate ECC "
             "key and/or certificate for OpenSK"))

  def create_tab_file(self, binaries):
    assert binaries
    assert self.args.application
    info("Generating Tock TAB file for application/example {}".format(
        self.args.application))
    elf2tab_ver = self.checked_command_output(
        ["elf2tab/bin/elf2tab", "--version"]).split(
            "\n", maxsplit=1)[0]
    if elf2tab_ver != "elf2tab 0.6.0":
      error(
          ("Detected unsupported elf2tab version {!a}. The following "
           "commands may fail. Please use 0.6.0 instead.").format(elf2tab_ver))
    os.makedirs(self.tab_folder, exist_ok=True)
    tab_filename = os.path.join(self.tab_folder,
                                "{}.tab".format(self.args.application))
    elf2tab_args = [
        "elf2tab/bin/elf2tab", "--deterministic", "--package-name",
        self.args.application, "-o", tab_filename
    ]
    if self.args.verbose_build:
      elf2tab_args.append("--verbose")
    for arch, app_file in binaries.items():
      dest_file = os.path.join(self.tab_folder, "{}.elf".format(arch))
      shutil.copyfile(app_file, dest_file)
      elf2tab_args.append(dest_file)

    elf2tab_args.extend([
        "--stack={}".format(STACK_SIZE), "--app-heap={}".format(APP_HEAP_SIZE),
        "--kernel-heap=1024", "--protected-region-size=64"
    ])
    if self.args.elf2tab_output:
      output = self.checked_command_output(elf2tab_args)
      self.args.elf2tab_output.write(output)
    else:
      self.checked_command(elf2tab_args)

  def install_tab_file(self, tab_filename):
    assert self.args.application
    info("Installing Tock application {}".format(self.args.application))
    board_props = SUPPORTED_BOARDS[self.args.board]
    args = copy.copy(self.tockloader_default_args)
    setattr(args, "app_address", board_props.app_address)
    setattr(args, "erase", self.args.clear_apps)
    setattr(args, "make", False)
    setattr(args, "no_replace", False)
    tock = loader.TockLoader(args)
    tock.open()
    tabs = [tab.TAB(tab_filename)]
    try:
      tock.install(tabs, replace="yes", erase=args.erase)
    except TockLoaderException as e:
      fatal("Couldn't install Tock application {}: {}".format(
          self.args.application, str(e)))

  def get_padding(self):
    padding = tbfh.TBFHeaderPadding(
        SUPPORTED_BOARDS[self.args.board].app_address -
        SUPPORTED_BOARDS[self.args.board].padding_address)
    return padding.get_binary()

  def install_tock_os(self):
    board_props = SUPPORTED_BOARDS[self.args.board]
    kernel_file = os.path.join("third_party", "tock", "target",
                               board_props.arch, "release",
                               "{}.bin".format(self.args.board))
    info("Flashing file {}.".format(kernel_file))
    with open(kernel_file, "rb") as f:
      kernel = f.read()
    args = copy.copy(self.tockloader_default_args)
    setattr(args, "address", board_props.app_address)
    tock = loader.TockLoader(args)
    tock.open()
    try:
      tock.flash_binary(kernel, board_props.kernel_address)
    except TockLoaderException as e:
      fatal("Couldn't install Tock OS: {}".format(str(e)))

  def install_padding(self):
    padding = self.get_padding()
    board_props = SUPPORTED_BOARDS[self.args.board]
    info("Flashing padding application")
    args = copy.copy(self.tockloader_default_args)
    setattr(args, "address", board_props.padding_address)
    tock = loader.TockLoader(args)
    tock.open()
    try:
      tock.flash_binary(padding, args.address)
    except TockLoaderException as e:
      fatal("Couldn't install padding: {}".format(str(e)))

  def clear_apps(self):
    args = copy.copy(self.tockloader_default_args)
    board_props = SUPPORTED_BOARDS[self.args.board]
    setattr(args, "app_address", board_props.app_address)
    # Ensure we don't force erase all apps but only the apps starting
    # at `board.app_address`. This makes sure we don't erase the padding.
    setattr(args, "force", False)
    info("Erasing all installed applications")
    tock = loader.TockLoader(args)
    tock.open()
    try:
      tock.erase_apps()
    except TockLoaderException as e:
      # Erasing apps is not critical
      info(("A non-critical error occurred while erasing "
            "apps: {}".format(str(e))))

  def clear_storage(self):
    if self.args.programmer == "none":
      return 0
    info("Erasing the persistent storage")
    board_props = SUPPORTED_BOARDS[self.args.board]
    # Use tockloader if possible
    if self.args.programmer in ("jlink", "openocd"):
      storage = bytes([0xFF] * board_props.storage_size)
      tock = loader.TockLoader(self.tockloader_default_args)
      tock.open()
      try:
        tock.flash_binary(storage, board_props.storage_address)
      except TockLoaderException as e:
        fatal("Couldn't erase the persistent storage: {}".format(str(e)))
      return 0
    if self.args.programmer == "pyocd":
      self.checked_command([
          "pyocd", "erase", "--target={}".format(board_props.pyocd_target),
          "--sector", "{}+{}".format(board_props.storage_address,
                                     board_props.storage_size)
      ])
      return 0
    fatal("Programmer {} is not supported.".format(self.args.programmer))

  # pylint: disable=protected-access
  def verify_flashed_app(self, expected_app):
    if self.args.programmer not in ("jlink", "openocd"):
      return False
    args = copy.copy(self.tockloader_default_args)
    tock = loader.TockLoader(args)
    tock.open()
    app_found = False
    with tock._start_communication_with_board():
      apps = [app.get_name() for app in tock._extract_all_app_headers()]
      app_found = expected_app in apps
    return app_found

  def create_hex_file(self, dest_file):
    # We produce an intelhex file with everything in it
    # https://en.wikipedia.org/wiki/Intel_HEX
    # pylint: disable=g-import-not-at-top,import-outside-toplevel
    import intelhex
    board_props = SUPPORTED_BOARDS[self.args.board]
    final_hex = intelhex.IntelHex()

    if self.args.tockos:
      # Process kernel
      kernel_path = os.path.join("third_party", "tock", "target",
                                 board_props.arch, "release",
                                 "{}.bin".format(self.args.board))
      with open(kernel_path, "rb") as kernel:
        kern_hex = intelhex.IntelHex()
        kern_hex.frombytes(kernel.read(), offset=board_props.kernel_address)
        final_hex.merge(kern_hex, overlap="error")

    if self.args.application:
      # Add padding
      if board_props.padding_address:
        padding_hex = intelhex.IntelHex()
        padding_hex.frombytes(
            self.get_padding(), offset=board_props.padding_address)
        final_hex.merge(padding_hex, overlap="error")

      # Now we can add the application from the TAB file
      app_tab_path = "target/tab/{}.tab".format(self.args.application)
      assert os.path.exists(app_tab_path)
      app_tab = tab.TAB(app_tab_path)
      if board_props.arch not in app_tab.get_supported_architectures():
        fatal(("It seems that the TAB file was not produced for the "
               "architecture {}".format(board_props.arch)))
      app_hex = intelhex.IntelHex()
      app_hex.frombytes(
          app_tab.extract_app(board_props.arch).get_binary(
              board_props.app_address),
          offset=board_props.app_address)
      final_hex.merge(app_hex)
    info("Generating all-merged HEX file: {}".format(dest_file))
    final_hex.tofile(dest_file, format="hex")

  def check_prerequisites(self):
    if not tockloader.__version__.startswith("1.5."):
      fatal(("Your version of tockloader seems incompatible: found {}, "
             "expected 1.5.x.".format(tockloader.__version__)))

    if self.args.programmer == "jlink":
      assert_mandatory_binary("JLinkExe")

    if self.args.programmer == "openocd":
      assert_mandatory_binary("openocd")

    if self.args.programmer == "pyocd":
      assert_mandatory_binary("pyocd")
      assert_python_library("intelhex")
      if not SUPPORTED_BOARDS[self.args.board].pyocd_target:
        fatal("This board doesn't seem to support flashing through pyocd.")

    if self.args.programmer == "nordicdfu":
      assert_mandatory_binary("nrfutil")
      assert_python_library("intelhex")
      assert_python_library("nordicsemi.lister")
      nrfutil_version = __import__("nordicsemi.version").version.NRFUTIL_VERSION
      if not nrfutil_version.startswith("6."):
        fatal(("You need to install nrfutil python3 package v6.0 or above. "
               "Found: {}".format(nrfutil_version)))
      if not SUPPORTED_BOARDS[self.args.board].nordic_dfu:
        fatal("This board doesn't support flashing over DFU.")

    if self.args.programmer == "none":
      assert_python_library("intelhex")

  def run(self):
    self.check_prerequisites()
    self.update_rustc_if_needed()

    if not (self.args.tockos or self.args.application or
            self.args.clear_storage):
      info("Nothing to do.")
      return 0

    # Compile what needs to be compiled
    if self.args.tockos:
      self.build_tockos()

    if self.args.application == "ctap2":
      self.generate_crypto_materials(self.args.regenerate_keys)
      self.build_opensk()
    elif self.args.application is None:
      info("No application selected.")
    else:
      self.build_example()

    # Erase persistent storage
    if self.args.clear_storage:
      self.clear_storage()

    # Flashing
    board_props = SUPPORTED_BOARDS[self.args.board]
    if self.args.programmer in ("jlink", "openocd"):
      # We rely on Tockloader to do the job
      if self.args.clear_apps:
        self.clear_apps()
      if self.args.tockos:
        # Install Tock OS
        self.install_tock_os()
      # Install padding and application if needed
      if self.args.application:
        self.install_padding()
        self.install_tab_file("target/tab/{}.tab".format(self.args.application))
        if self.verify_flashed_app(self.args.application):
          info("You're all set!")
          return 0
        error(
            ("It seems that something went wrong. App/example not found "
             "on your board. Ensure the connections between the programmer and "
             "the board are correct."))
        return 1
      return 0

    if self.args.programmer in ("pyocd", "nordicdfu", "none"):
      dest_file = "target/{}_merged.hex".format(self.args.board)
      os.makedirs("target", exist_ok=True)
      self.create_hex_file(dest_file)

      if self.args.programmer == "pyocd":
        info("Flashing HEX file")
        self.checked_command([
            "pyocd", "flash", "--target={}".format(board_props.pyocd_target),
            "--format=hex", "--erase=auto", dest_file
        ])
      if self.args.programmer == "nordicdfu":
        info("Creating DFU package")
        dfu_pkg_file = "target/{}_dfu.zip".format(self.args.board)
        self.checked_command([
            "nrfutil", "pkg", "generate", "--hw-version=52", "--sd-req=0",
            "--application-version=1", "--application={}".format(dest_file),
            dfu_pkg_file
        ])
        info(
            "Please insert the dongle and switch it to DFU mode by keeping the "
            "button pressed while inserting...")
        info("Press [ENTER] when ready.")
        _ = input()
        # Search for the DFU devices
        serial_number = []
        # pylint: disable=g-import-not-at-top,import-outside-toplevel
        from nordicsemi.lister import device_lister
        for device in device_lister.DeviceLister().enumerate():
          if device.vendor_id == "1915" and device.product_id == "521F":
            serial_number.append(device.serial_number)
        if not serial_number:
          fatal("Couldn't find any DFU device on your system.")
        if len(serial_number) > 1:
          fatal("Multiple DFU devices are detected. Please only connect one.")
        # Run the command without capturing stdout so that we show progress
        info("Flashing device using DFU...")
        return subprocess.run(
            [
                "nrfutil", "dfu", "usb-serial",
                "--package={}".format(dfu_pkg_file),
                "--serial-number={}".format(serial_number[0])
            ],
            check=False,
            timeout=None,
        ).returncode

    # Configure OpenSK through vendor specific command if needed
    if any([
        self.args.lock_device,
        self.args.config_cert,
        self.args.config_pkey,
    ]):
      # pylint: disable=g-import-not-at-top,import-outside-toplevel
      import tools.configure
      tools.configure.main(
          argparse.Namespace(
              batch=False,
              certificate=self.args.config_cert,
              priv_key=self.args.config_pkey,
              lock=self.args.lock_device,
          ))
    return 0


def main(args):
  colorama.init()

  # Make sure the current working directory is the right one before running
  os.chdir(os.path.realpath(os.path.dirname(__file__)))

  if args.listing == "boards":
    print(os.linesep.join(get_supported_boards()))
    return 0

  if args.listing == "programmers":
    print(os.linesep.join(PROGRAMMERS))
    return 0

  if args.listing:
    # Missing check?
    fatal("Listing {} is not implemented.".format(args.listing))

  OpenSKInstaller(args).run()


if __name__ == "__main__":
  main_parser = argparse.ArgumentParser()
  action_group = main_parser.add_mutually_exclusive_group(required=True)
  action_group.add_argument(
      "--list",
      metavar="WHAT",
      choices=("boards", "programmers"),
      default=None,
      dest="listing",
      help="List supported boards or programmers, 1 per line and then exit.",
  )
  action_group.add_argument(
      "--board",
      metavar="BOARD_NAME",
      dest="board",
      default=None,
      choices=get_supported_boards(),
      help="Indicates which board Tock OS will be compiled for.",
  )

  main_parser.add_argument(
      "--dont-clear-apps",
      action="store_false",
      default=True,
      dest="clear_apps",
      help=("When installing an application, previously installed "
            "applications won't be erased from the board."),
  )
  main_parser.add_argument(
      "--clear-storage",
      action="store_true",
      default=False,
      dest="clear_storage",
      help=("Erases the persistent storage when installing an application. "
            "All stored data will be permanently lost."),
  )
  main_parser.add_argument(
      "--lock-device",
      action="store_true",
      default=False,
      dest="lock_device",
      help=("Try to disable JTAG at the end of the operations. This "
            "operation may fail if the device is already locked or if "
            "the certificate/private key are not programmed."),
  )
  main_parser.add_argument(
      "--inject-certificate",
      default=None,
      metavar="PEM_FILE",
      type=argparse.FileType("rb"),
      dest="config_cert",
      help=("If this option is set, the corresponding certificate "
            "will be programmed into the key as the last operation."),
  )
  main_parser.add_argument(
      "--inject-private-key",
      default=None,
      metavar="PEM_FILE",
      type=argparse.FileType("rb"),
      dest="config_pkey",
      help=("If this option is set, the corresponding private key "
            "will be programmed into the key as the last operation."),
  )
  main_parser.add_argument(
      "--programmer",
      metavar="METHOD",
      dest="programmer",
      choices=PROGRAMMERS,
      default="jlink",
      help=("Sets the method to be used to flash Tock OS or the application "
            "on the target board."),
  )

  main_parser.add_argument(
      "--no-tockos",
      action="store_false",
      default=True,
      dest="tockos",
      help=("Only compiles and flash the application/example. "
            "Otherwise TockOS will also be bundled and flashed."),
  )
  main_parser.add_argument(
      "--verbose-build",
      action="store_true",
      default=False,
      dest="verbose_build",
      help="Build everything in verbose mode.",
  )

  main_parser.add_argument(
      "--panic-console",
      action="append_const",
      const="panic_console",
      dest="features",
      help=("In case of application panic, the console will be used to "
            "output messages before starting blinking the LEDs on the "
            "board."),
  )
  main_parser.add_argument(
      "--debug",
      action="append_const",
      const="debug_ctap",
      dest="features",
      help=("Compiles and installs the OpenSK application in debug mode "
            "(i.e. more debug messages will be sent over the console port "
            "such as hexdumps of packets)."),
  )
  main_parser.add_argument(
      "--debug-allocations",
      action="append_const",
      const="debug_allocations",
      dest="features",
      help=("The console will be used to output allocator statistics every "
            "time an allocation/deallocation happens."),
  )
  main_parser.add_argument(
      "--verbose",
      action="append_const",
      const="verbose",
      dest="features",
      help=("The console will be used to output verbose information about the "
            "OpenSK application. This also automatically activates --debug."),
  )
  main_parser.add_argument(
      "--no-u2f",
      action=RemoveConstAction,
      const="with_ctap1",
      dest="features",
      help=("Compiles the OpenSK application without backward compatible "
            "support for U2F/CTAP1 protocol."),
  )
  main_parser.add_argument(
      "--ctap2.1",
      action="append_const",
      const="with_ctap2_1",
      dest="features",
      help=("Compiles the OpenSK application with backward compatible "
            "support for CTAP2.1 protocol."),
  )
  main_parser.add_argument(
      "--nfc",
      action="append_const",
      const="with_nfc",
      dest="features",
      help=("Compiles the OpenSK application with support for nfc."),
  )
  main_parser.add_argument(
      "--regen-keys",
      action="store_true",
      default=False,
      dest="regenerate_keys",
      help=("Forces the generation of files (certificates and private keys) "
            "under the crypto_data/ directory. "
            "This is useful to allow flashing multiple OpenSK authenticators "
            "in a row without them being considered clones."),
  )

  main_parser.add_argument(
      "--elf2tab-output",
      metavar="FILE",
      type=argparse.FileType("a"),
      dest="elf2tab_output",
      default=None,
      help=("When set, the output of elf2tab is appended to this file."),
  )

  main_parser.set_defaults(features=["with_ctap1"])

  # Start parsing to know if we're going to list things or not.
  partial_args, _ = main_parser.parse_known_args()

  # We only need the apps_group if we have a board set
  apps_group = main_parser.add_mutually_exclusive_group(
      required=(partial_args.board is not None))
  apps_group.add_argument(
      "--no-app",
      dest="application",
      action="store_const",
      const=None,
      help=("Doesn't compile nor install any application. Useful when you only "
            "want to update Tock OS kernel."))
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
      help=("Compiles and installs the crypto_bench example that benchmarks "
            "the performance of the cryptographic algorithms on the board."))
  apps_group.add_argument(
      "--store_latency",
      dest="application",
      action="store_const",
      const="store_latency",
      help=("Compiles and installs the store_latency example which print "
            "latency statistics of the persistent store library."))
  apps_group.add_argument(
      "--erase_storage",
      dest="application",
      action="store_const",
      const="erase_storage",
      help=("Compiles and installs the erase_storage example which erases "
            "the storage. During operation the dongle red light is on. Once "
            "the operation is completed the dongle green light is on."))
  apps_group.add_argument(
      "--panic_test",
      dest="application",
      action="store_const",
      const="panic_test",
      help=("Compiles and installs the panic_test example that immediately "
            "triggers a panic."))
  apps_group.add_argument(
      "--oom_test",
      dest="application",
      action="store_const",
      const="oom_test",
      help=("Compiles and installs the oom_test example that tests the "
            "allocator until an out-of-memory error occurs."))
  apps_group.add_argument(
      "--console_test",
      dest="application",
      action="store_const",
      const="console_test",
      help=("Compiles and installs the console_test example that tests the "
            "console driver with messages of various lengths."))
  apps_group.add_argument(
      "--nfct_test",
      dest="application",
      action="store_const",
      const="nfct_test",
      help=("Compiles and installs the nfct_test example that tests the "
            "NFC driver."))

  main(main_parser.parse_args())
