#!py_virtual_env/bin/python3
# Copyright 2019-2023 Google LLC
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
import time
from typing import Dict, List, Tuple

import colorama
from six.moves import input
import tockloader
from tockloader import tab
from tockloader import tbfh
from tockloader import tockloader as loader
from tockloader.exceptions import TockLoaderException

import tools.configure
from tools.deploy_partition import create_metadata, load_priv_key, pad_to

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
        # Set to None if padding is not required for the board.
        # This creates a fake Tock OS application that starts at the
        # address specified by this parameter (must match the `prog` value
        # specified on the board's `layout.ld` file) and will end at
        # `app_address`.
        "padding_address",
        # If present, enforce that the firmware image equals this value,
        # padding it with 0xFF bytes.
        "firmware_size",
        # Set to None if metadata is not required for the board.
        # Writes the metadata that is checked by the custom bootloader for
        # upgradable board.
        "metadata_address",
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

nrf52840dk_opensk_board = OpenSKBoard(
    path="third_party/tock/boards/nordic/nrf52840dk_opensk",
    arch="thumbv7em-none-eabi",
    page_size=4096,
    kernel_address=0,
    padding_address=0x30000,
    firmware_size=None,
    metadata_address=None,
    app_ldscript="nrf52840_layout.ld",
    app_address=0x40000,
    storage_address=0xC0000,
    storage_size=0x14000,
    pyocd_target="nrf52840",
    openocd_board="nordic_nrf52840_dongle.cfg",
    openocd_options=[],
    openocd_commands={},
    jlink_if="swd",
    jlink_device="nrf52840_xxaa",
    nordic_dfu=False,
)

SUPPORTED_BOARDS = {
    "nrf52840dk_opensk":
        nrf52840dk_opensk_board,
    "nrf52840dk_opensk_a":
        nrf52840dk_opensk_board._replace(
            path=nrf52840dk_opensk_board.path + "_a",
            kernel_address=0x20000,
            padding_address=None,
            firmware_size=0x40000,
            metadata_address=0x4000,
            app_ldscript="nrf52840_layout_a.ld",
            app_address=0x40000,
        ),
    "nrf52840dk_opensk_b":
        nrf52840dk_opensk_board._replace(
            path=nrf52840dk_opensk_board.path + "_b",
            kernel_address=0x60000,
            padding_address=None,
            firmware_size=0x40000,
            metadata_address=0x5000,
            app_ldscript="nrf52840_layout_b.ld",
            app_address=0x80000,
        ),
    "nrf52840_dongle_opensk":
        nrf52840dk_opensk_board._replace(
            path="third_party/tock/boards/nordic/nrf52840_dongle_opensk",),
    "nrf52840_dongle_dfu":
        nrf52840dk_opensk_board._replace(
            path="third_party/tock/boards/nordic/nrf52840_dongle_dfu",
            kernel_address=0x1000,
            nordic_dfu=True,
        ),
    "nrf52840_mdk_dfu":
        nrf52840dk_opensk_board._replace(
            path="third_party/tock/boards/nordic/nrf52840_mdk_dfu",
            kernel_address=0x1000,
            nordic_dfu=True,
        ),
}

# The following value must match the one used in the file
# `src/entry_point.rs`
APP_HEAP_SIZE = 90_000

CARGO_TARGET_DIR = os.environ.get("CARGO_TARGET_DIR", "target")


def get_supported_boards() -> Tuple[str]:
  """Returns a tuple all valid supported boards."""
  boards = []
  for name, props in SUPPORTED_BOARDS.items():
    if all((os.path.exists(os.path.join(props.path, "Cargo.toml")),
            (props.app_ldscript and os.path.exists(props.app_ldscript)))):
      boards.append(name)
  return tuple(set(boards))


def fatal(msg: str):
  print(f"{colorama.Fore.RED + colorama.Style.BRIGHT}fatal:"
        f"{colorama.Style.RESET_ALL} {msg}")
  sys.exit(1)


def error(msg: str):
  print(f"{colorama.Fore.RED}error:{colorama.Style.RESET_ALL} {msg}")


def info(msg: str):
  print(f"{colorama.Fore.GREEN + colorama.Style.BRIGHT}info:"
        f"{colorama.Style.RESET_ALL} {msg}")


def assert_mandatory_binary(binary_name: str):
  if not shutil.which(binary_name):
    fatal((f"Couldn't find {binary_name} binary. Make sure it is installed and "
           "that your PATH is set correctly."))


def assert_python_library(module: str):
  try:
    __import__(module)
  except ModuleNotFoundError:
    fatal((f"Couldn't load python3 module {module}. "
           f"Try to run: pip3 install {module}"))


class RemoveConstAction(argparse.Action):

  # pylint: disable=redefined-builtin
  # pylint: disable=too-many-positional-arguments
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
  """Checks, builds and installs various parts of OpenSK.

  This module can perform the following tasks:
    - build and install Tock OS
    - check, build and install the main ctap2 application
    - build and install example applications
    - write padding
    - erase apps and persistent storage
    - write metadata entries for upgradable boards

    OpenSKInstaller(args).run()
  """

  def __init__(self, args):
    self.args = args
    # Where all the TAB files should go
    self.tab_folder = os.path.join(CARGO_TARGET_DIR, "tab")
    board = SUPPORTED_BOARDS[self.args.board]
    self.tockloader_default_args = argparse.Namespace(
        app_address=board.app_address,
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
        openocd_cmd=self.args.openocd_cmd,
        openocd_commands=copy.copy(board.openocd_commands),
        openocd_options=copy.copy(board.openocd_options),
        jtag=False,
        no_bootloader_entry=False,
        page_size=board.page_size,
        port=None,
    )

  def checked_command(self,
                      cmd: List[str],
                      env: Dict[str, str] = None,
                      cwd: str = None):
    """Executes the given command.

    Outside of debug mode, the command's output is muted. Exits if the called
    process returns an error.

    Args:
      cmd: A list of strings. The first string is the command, the other list
      elements are parameters to that command."
      env: The dictionary of environment variables.
      cwd: The directory to execute from.
    """
    stdout = None if self.args.verbose_build else subprocess.DEVNULL
    try:
      subprocess.run(
          cmd, stdout=stdout, timeout=None, check=True, env=env, cwd=cwd)
    except subprocess.CalledProcessError as e:
      fatal(f"Failed to execute {cmd[0]}: {str(e)}")

  def checked_command_output(self,
                             cmd: List[str],
                             env: Dict[str, str] = None,
                             cwd: str = None) -> str:
    """Executes cmd like checked_command, but returns the output."""
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
      fatal(f"Failed to execute {cmd[0]}: {str(e)}")
      # Unreachable because fatal() will exit
    return cmd_output.decode()

  def build_tockos(self):
    """Buids Tock OS with the parameters specified in args."""
    info(f"Building Tock OS for board {self.args.board}")
    props = SUPPORTED_BOARDS[self.args.board]
    out_directory = os.path.join("third_party", "tock", "target", props.arch,
                                 "release")
    os.makedirs(out_directory, exist_ok=True)

    env = os.environ.copy()
    if self.args.verbose_build:
      env["V"] = "1"
    if "vendor_hid" in self.args.features:
      env["CARGO_FLAGS"] = "--features=vendor_hid"
    self.checked_command(["make"], cwd=props.path, env=env)

  def build_example(self):
    """Builds an example with the name from args."""
    info(f"Building example {self.args.application}")
    self._build_app_or_example(is_example=True)

  def build_opensk(self):
    """Runs essential tests in OpenSK, then builds it if successful."""
    info("Building OpenSK application")
    self._check_invariants()
    self._build_app_or_example(is_example=False)

  def build_bootloader(self):
    """Builds the upgrade bootloader."""
    props = SUPPORTED_BOARDS[self.args.board]
    info("Building bootloader")
    rust_flags = [
        f"--remap-path-prefix={os.getcwd()}=",
        "-C",
        "link-arg=-Wl,-Tlink.x",
        "-C",
        "link-arg=-nostartfiles",
    ]
    env = os.environ.copy()
    env["RUSTFLAGS"] = " ".join(rust_flags)
    cargo_command = ["cargo", "build", "--release", f"--target={props.arch}"]
    self.checked_command(cargo_command, cwd="bootloader", env=env)
    binary_path = os.path.join(CARGO_TARGET_DIR, props.arch, "release",
                               "bootloader")
    objcopy_command = [
        "llvm-objcopy", "-O", "binary", binary_path, f"{binary_path}.bin"
    ]
    self.checked_command(objcopy_command, cwd="bootloader")

  def flash_bootloader(self):
    """Flashes the upgrade bootloader."""
    props = SUPPORTED_BOARDS[self.args.board]
    info("Flashing bootloader")
    bin_file = os.path.join("bootloader", "target", props.arch, "release",
                            "bootloader.bin")
    if not os.path.exists(bin_file):
      fatal(f"File not found: {bin_file}")
    with open(bin_file, "rb") as bootloader_bin:
      bootloader = bootloader_bin.read()
    self.write_binary(bootloader, 0)

  def _build_app_or_example(self, is_example: bool):
    """Builds the application specified through args.

    This function specifies the used compile time flags, specifying the linker
    script and reducing the binary size. It compiles the application and calls
    elf2tab to create a TAB file out of the produced binary.

    The settings in self.args have to match is_example.

    Args:
      is_example: Whether args.application is an example or the main ctap2 app.
    """
    assert self.args.application
    # Ideally we would build a TAB file for all boards at once but depending on
    # the chip on the board, the link script could be totally different.
    # And elf2tab doesn't seem to let us set the boards a TAB file has been
    # created for. So at the moment we only build for the selected board.
    props = SUPPORTED_BOARDS[self.args.board]
    rust_flags = [
        "-C",
        f"link-arg=-T{props.app_ldscript}",
        "-C",
        "relocation-model=static",
        "-D",
        "warnings",
        f"--remap-path-prefix={os.getcwd()}=",
        "-C",
        "link-arg=-icf=all",
        "-C",
        "force-frame-pointers=no",
    ]
    env = os.environ.copy()
    env["RUSTFLAGS"] = " ".join(rust_flags)
    env["APP_HEAP_SIZE"] = str(APP_HEAP_SIZE)

    command = [
        "cargo",
        "build",
        "--release",
        f"--target={props.arch}",
        f"--features={','.join(self.args.features)}"  # pylint: disable=W1405
    ]
    if is_example:
      command.extend(["--example", self.args.application])
    if self.args.verbose_build:
      command.append("--verbose")
    self.checked_command(command, env=env)
    app_path = os.path.join(CARGO_TARGET_DIR, props.arch, "release")
    if is_example:
      app_path = os.path.join(app_path, "examples")
    app_path = os.path.join(app_path, self.args.application)
    # Create a TAB file
    self.create_tab_file({props.arch: app_path})

  def _check_invariants(self):
    """Runs selected unit tests to check preconditions in the code."""
    print("Testing invariants in customization.rs...")
    features = ["std"]
    features.extend(self.args.features)
    self.checked_command_output([
        "cargo",
        "test",
        f"--features={','.join(features)}",  # pylint: disable=W1405
        "--lib",
        "customization"
    ])

  def generate_crypto_materials(self, force_regenerate: bool):
    """Calls a shell script that generates cryptographic material."""
    has_error = subprocess.call([
        os.path.join("tools", "gen_key_materials.sh"),
        "Y" if force_regenerate else "N",
    ])
    if has_error:
      error(("Something went wrong while trying to generate ECC "
             "key and/or certificate for OpenSK"))

  def create_tab_file(self, binary_names: Dict[str, str]):
    """Checks and uses elf2tab to generated an TAB file out of the binaries."""
    assert binary_names
    assert self.args.application
    info("Generating Tock TAB file for application/example "
         f"{self.args.application}")
    elf2tab_ver = self.checked_command_output(
        ["elf2tab/bin/elf2tab", "--version"]).split(
            "\n", maxsplit=1)[0]
    if elf2tab_ver != "elf2tab 0.10.2":
      error(("Detected unsupported elf2tab version {elf2tab_ver!a}! The "
             "following commands may fail. Please use 0.10.2 instead."))
    os.makedirs(self.tab_folder, exist_ok=True)
    tab_filename = os.path.join(self.tab_folder, f"{self.args.application}.tab")
    supported_kernel = (2, 1)
    elf2tab_args = [
        "elf2tab/bin/elf2tab", "--deterministic", "--package-name",
        self.args.application, f"--kernel-major={supported_kernel[0]}",
        f"--kernel-minor={supported_kernel[1]}", "-o", tab_filename
    ]
    if self.args.verbose_build:
      elf2tab_args.append("--verbose")
    stack_sizes = set()
    for arch, app_file in binary_names.items():
      dest_file = os.path.join(self.tab_folder, f"{arch}.elf")
      shutil.copyfile(app_file, dest_file)
      elf2tab_args.append(dest_file)
      # extract required stack size directly from binary
      nm = self.checked_command_output(
          ["nm", "--print-size", "--radix=x", app_file])
      for line in nm.splitlines():
        if "STACK_MEMORY" in line:
          required_stack_size = int(line.split(" ", maxsplit=2)[1], 16)
          stack_sizes.add(required_stack_size)
    if len(stack_sizes) != 1:
      error("Detected different stack sizes across tab files.")
    # `protected-region-size` must match the `TBF_HEADER_SIZE`
    # (currently 0x60 = 96 bytes)
    elf2tab_args.extend([
        f"--stack={stack_sizes.pop()}", f"--app-heap={APP_HEAP_SIZE}",
        "--kernel-heap=1024", "--protected-region-size=96"
    ])
    if self.args.elf2tab_output:
      output = self.checked_command_output(elf2tab_args)
      self.args.elf2tab_output.write(output)
    else:
      self.checked_command(elf2tab_args)

  def install_tab_file(self, tab_filename: str):
    """Calls Tockloader to install a TAB file."""
    assert self.args.application
    info(f"Installing Tock application {self.args.application}")
    args = copy.copy(self.tockloader_default_args)
    setattr(args, "erase", self.args.clear_apps)
    setattr(args, "make", False)
    setattr(args, "no_replace", False)
    tock = loader.TockLoader(args)
    tock.open()
    tabs = [tab.TAB(tab_filename)]
    try:
      tock.install(tabs, replace="yes", erase=args.erase)
    except TockLoaderException as e:
      fatal("Couldn't install Tock application "
            f"{self.args.application}: {str(e)}")

  def get_padding(self) -> bytes:
    """Creates a padding application binary."""
    padding = tbfh.TBFHeaderPadding(
        SUPPORTED_BOARDS[self.args.board].app_address -
        SUPPORTED_BOARDS[self.args.board].padding_address)
    return padding.get_binary()

  def write_binary(self, binary: bytes, address: int):
    """Writes a binary to the device's flash at the given address."""
    tock = loader.TockLoader(self.tockloader_default_args)
    tock.open()
    try:
      tock.flash_binary(binary, address)
    except TockLoaderException as e:
      fatal(f"Couldn't write binary: {str(e)}")

  def read_kernel(self) -> bytes:
    """Reads the kernel file from disk and returns it as a byte array."""
    board_props = SUPPORTED_BOARDS[self.args.board]
    kernel_file = os.path.join("third_party", "tock", "target",
                               board_props.arch, "release",
                               f"{self.args.board}.bin")
    if not os.path.exists(kernel_file):
      fatal(f"File not found: {kernel_file}")
    with open(kernel_file, "rb") as firmware:
      kernel = firmware.read()

    # Pads the kernel to the expected length.
    if board_props.padding_address is None:
      end_address = board_props.app_address
    else:
      end_address = board_props.padding_address
    kernel_size = end_address - board_props.kernel_address
    return pad_to(kernel, kernel_size)

  def install_tock_os(self):
    """Reads the kernel from disk and writes it to the device's flash."""
    kernel = self.read_kernel()
    board_props = SUPPORTED_BOARDS[self.args.board]
    self.write_binary(kernel, board_props.kernel_address)

  def install_padding(self):
    """Generates a padding application and writes it to the address in args."""
    board_props = SUPPORTED_BOARDS[self.args.board]
    if board_props.padding_address is None:
      return
    info("Flashing padding application")
    self.write_binary(self.get_padding(), board_props.padding_address)

  def install_metadata(self):
    """Generates and writes firmware metadata at the metadata address."""
    board_props = SUPPORTED_BOARDS[self.args.board]
    if board_props.metadata_address is None:
      return

    kernel = self.read_kernel()
    app_tab_path = f"{CARGO_TARGET_DIR}/tab/ctap2.tab"
    if not os.path.exists(app_tab_path):
      fatal(f"File not found: {app_tab_path}")
    app_tab = tab.TAB(app_tab_path)
    arch = board_props.arch
    if arch not in app_tab.get_supported_architectures():
      fatal(f"Architecture not found: {arch}")
    app = app_tab.extract_app(arch).get_binary(board_props.app_address)

    kernel_size = board_props.app_address - board_props.kernel_address
    app_size = board_props.firmware_size - kernel_size
    # The kernel is already padded when read.
    firmware_image = kernel + pad_to(app, app_size)

    priv_key = load_priv_key(self.args.upgrade_priv_key)
    metadata = create_metadata(firmware_image, board_props.kernel_address,
                               self.args.version, priv_key)
    if self.args.verbose_build:
      info(f"Metadata bytes: {metadata}")

    info("Flashing metadata application")
    self.write_binary(metadata, board_props.metadata_address)

  def clear_apps(self):
    """Uses Tockloader to erase all applications on the device."""
    args = copy.copy(self.tockloader_default_args)
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
      info(f"A non-critical error occurred while erasing apps: {str(e)}")

  def clear_storage(self):
    """Overwrites the storage's flash with 0xFF bytes."""
    if self.args.programmer == "none":
      return 0
    info("Erasing the persistent storage")
    board_props = SUPPORTED_BOARDS[self.args.board]
    # Use tockloader if possible
    if self.args.programmer in ("jlink", "openocd"):
      storage = bytes([0xFF] * board_props.storage_size)
      self.write_binary(storage, board_props.storage_address)
      return 0
    if self.args.programmer == "pyocd":
      self.checked_command([
          "pyocd", "erase", f"--target={board_props.pyocd_target}", "--sector",
          f"{board_props.storage_address}+{board_props.storage_size}"
      ])
      return 0
    fatal(f"Programmer {self.args.programmer} is not supported.")

  # pylint: disable=protected-access
  def verify_flashed_app(self, expected_app: str) -> bool:
    """Uses Tockloader to check if an app of the expected name was written."""
    if self.args.programmer not in ("jlink", "openocd"):
      return False
    tock = loader.TockLoader(self.tockloader_default_args)
    tock.open()
    app_found = False
    with tock._start_communication_with_board():
      apps = [app.get_name() for app in tock._extract_all_app_headers()]
      app_found = expected_app in apps
    return app_found

  def create_hex_file(self, dest_file: str):
    """Creates an intelhex file from the kernel and app binaries on disk."""
    # We produce an intelhex file with everything in it
    # https://en.wikipedia.org/wiki/Intel_HEX
    # pylint: disable=g-import-not-at-top,import-outside-toplevel
    import intelhex
    board_props = SUPPORTED_BOARDS[self.args.board]
    final_hex = intelhex.IntelHex()

    if self.args.tockos:
      # Process kernel
      kern_hex = intelhex.IntelHex()
      kern_hex.frombytes(self.read_kernel(), offset=board_props.kernel_address)
      final_hex.merge(kern_hex, overlap="error")

    if self.args.application:
      # Add padding
      if board_props.padding_address:
        padding_hex = intelhex.IntelHex()
        padding_hex.frombytes(
            self.get_padding(), offset=board_props.padding_address)
        final_hex.merge(padding_hex, overlap="error")

      # Now we can add the application from the TAB file
      app_tab_path = f"{CARGO_TARGET_DIR}/tab/{self.args.application}.tab"
      assert os.path.exists(app_tab_path)
      app_tab = tab.TAB(app_tab_path)
      if board_props.arch not in app_tab.get_supported_architectures():
        fatal(("It seems that the TAB file was not produced for the "
               "architecture {board_props.arch}"))
      app_hex = intelhex.IntelHex()
      tab_bytes = app_tab.extract_app(board_props.arch).get_binary(
          board_props.app_address)
      if tab_bytes is None:
        fatal("The extracted bytes from the TAB file are none")
      app_hex.frombytes(tab_bytes, offset=board_props.app_address)
      final_hex.merge(app_hex)
    info(f"Generating all-merged HEX file: {dest_file}")
    final_hex.tofile(dest_file, format="hex")

  def check_prerequisites(self):
    """Checks versions of the used tools, exits on version mismatch."""
    if not tockloader.__version__.startswith("1.5."):
      fatal(("Your version of tockloader seems incompatible: found "
             f"{tockloader.__version__}, expected 1.5.x."))

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
               f"Found: v{nrfutil_version}. If you use Python >= 3.11, please "
               "try version 3.10."))
      if not SUPPORTED_BOARDS[self.args.board].nordic_dfu:
        fatal("This board doesn't support flashing over DFU.")

    if self.args.programmer == "none":
      assert_python_library("intelhex")

  def configure_device(self):
    """Checks the device configuration, and sets it according to args."""
    configure_response = tools.configure.main(
        argparse.Namespace(
            batch=False,
            certificate=self.args.config_cert,
            priv_key=self.args.config_pkey,
            lock=self.args.lock_device,
            use_vendor_hid="vendor_hid" in self.args.features,
        ))
    if not configure_response:
      return None
    return configure_response[0]

  def run(self) -> int:
    """Reads args to decide and run all required tasks."""
    self.check_prerequisites()

    if not (self.args.tockos or self.args.application or
            self.args.clear_storage or self.args.configure):
      info("Nothing to do.")
      return 0

    if self.args.check_patches:
      subprocess.run(["./maintainers/patches", "check"], check=False)

    # Compile what needs to be compiled
    board_props = SUPPORTED_BOARDS[self.args.board]
    if self.args.tockos:
      self.build_tockos()

    if board_props.metadata_address is not None:
      self.build_bootloader()

    if self.args.application == "ctap2":
      self.generate_crypto_materials(self.args.regenerate_keys)
      self.build_opensk()
    elif self.args.application is None:
      info("No application selected.")
    else:
      self.build_example()
      self.args.configure = False

    # Erase persistent storage
    if self.args.clear_storage:
      self.clear_storage()

    if "debug_ctap" in self.args.features:
      error("The debug feature does not work correctly on this branch. "
            "For development and debugging, please use the develop branch.")

    # Flashing
    if self.args.programmer in ("jlink", "openocd"):
      # We rely on Tockloader to do the job
      if self.args.clear_apps:
        self.clear_apps()
      if self.args.tockos:
        # Install Tock OS
        self.install_tock_os()
      if board_props.metadata_address is not None:
        # Install the bootloader
        self.flash_bootloader()
      # Install padding and application if needed
      if self.args.application:
        self.install_padding()
        self.install_tab_file(
            f"{CARGO_TARGET_DIR}/tab/{self.args.application}.tab")
        self.install_metadata()
        if not self.verify_flashed_app(self.args.application):
          error(("It seems that something went wrong. App/example not found "
                 "on your board. Ensure the connections between the programmer "
                 "and the board are correct."))
          return 1

    elif self.args.programmer in ("pyocd", "nordicdfu", "none"):
      dest_file = f"{CARGO_TARGET_DIR}/{self.args.board}_merged.hex"
      os.makedirs(CARGO_TARGET_DIR, exist_ok=True)
      self.create_hex_file(dest_file)

      if self.args.programmer == "pyocd":
        info("Flashing HEX file")
        self.checked_command([
            "pyocd", "flash", f"--target={board_props.pyocd_target}",
            "--format=hex", "--erase=auto", dest_file
        ])
      if self.args.programmer == "nordicdfu":
        info("Creating DFU package")
        dfu_pkg_file = f"{CARGO_TARGET_DIR}/{self.args.board}_dfu.zip"
        self.checked_command([
            "nrfutil", "pkg", "generate", "--hw-version=52", "--sd-req=0",
            "--application-version=1", f"--application={dest_file}",
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
        dfu_return_code = subprocess.run(
            [
                "nrfutil", "dfu", "usb-serial", f"--package={dfu_pkg_file}",
                f"--serial-number={serial_number[0]}"
            ],
            check=False,
            timeout=None,
        ).returncode
        if dfu_return_code != 0:
          return dfu_return_code

    # Configure OpenSK through vendor specific command if needed
    if self.args.programmer == "none":
      if any([
          self.args.lock_device,
          self.args.config_cert,
          self.args.config_pkey,
      ]):
        fatal("Unexpected arguments to configure your device. Since you "
              "selected the programmer \"none\", the device is not ready to be "
              "configured yet.")
      return 0

    # Perform checks if OpenSK was flashed.
    if self.args.application == "ctap2" or self.args.configure:
      self.configure()
    return 0

  def print_configure_help(self):
    vendor_hid = " --vendor-hid" if "vendor_hid" in self.args.features else ""
    info("Your device is not yet configured, and lacks some functionality. "
         "You can check its configuration status with:\n\n"
         f"./tools/configure.py{vendor_hid}\n\n"
         "If you run into issues, this command might help:\n\n"
         f"./tools/configure.py{vendor_hid} \\\n"
         "    --certificate=crypto_data/opensk_cert.pem \\\n"
         "    --private-key=crypto_data/opensk.key\n\n"
         "Please read the Certificate considerations in docs/customization.md"
         " to understand the privacy trade-off.")

  def configure(self):
    info("Configuring device.")
    # Trying to check or configure the device. Booting might take some time.
    for i in range(5):
      # Increasing wait time, total of 10 seconds.
      time.sleep(i)
      devices = tools.configure.get_opensk_devices(False)
      if devices:
        break

    if not devices:
      self.print_configure_help()
      fatal("No device to configure found.")
    status = self.configure_device()
    if not status:
      fatal("Could not read device configuration.")

    if status["cert"] and status["pkey"]:
      info("You're all set!")
    else:
      self.print_configure_help()
    return 0


def main(args):
  """Verifies some args, then runs a new OpenSKInstaller."""
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
    fatal(f"Listing {args.listing} is not implemented.")

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
            "the certificate/private key are not programmed."
            "Currently not implemented on nrf52840 and always fails."),
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
      "--openocd_cmd",
      dest="openocd_cmd",
      metavar="CMD",
      default="openocd",
      help=("Specifies a custom command to use when calling openocd. Can be "
            "used to pass arguments i.e. 'openocd -s /tmp/openocd_scripts'."),
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
      "--no-config-command",
      action=RemoveConstAction,
      const="config_command",
      dest="features",
      help=("Removes the AuthenticatorConfig command."),
  )
  main_parser.add_argument(
      "--rust-crypto",
      action="append_const",
      const="rust_crypto",
      dest="features",
      help=("Compiles the OpenSK application with RustCrypto implementations."),
  )
  main_parser.add_argument(
      "--nfc",
      action="append_const",
      const="with_nfc",
      dest="features",
      help=("Compiles the OpenSK application with support for nfc."),
  )
  main_parser.add_argument(
      "--configure",
      action="store_true",
      default=True,
      dest="configure",
      help="Configure.",
  )
  main_parser.add_argument(
      "--vendor-hid",
      action="append_const",
      const="vendor_hid",
      dest="features",
      help=("Compiles the OpenSK application to support two HID usage pages."),
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

  main_parser.add_argument(
      "--ed25519",
      action="append_const",
      const="ed25519",
      dest="features",
      help=("Adds support for credentials that use EdDSA algorithm over "
            "curve Ed25519. "
            "Current implementation is not side-channel resilient due to use "
            "of variable-time arithmetic for computations over secret key."),
  )

  main_parser.add_argument(
      "--disable-check-patches",
      action="store_false",
      default=True,
      dest="check_patches",
      help=("Don't check that patches are in sync with their submodules."),
  )

  main_parser.add_argument(
      "--private-key",
      type=str,
      default="crypto_data/opensk_upgrade.key",
      dest="upgrade_priv_key",
      help=("PEM file for signing the firmware."),
  )

  main_parser.add_argument(
      "--version",
      type=int,
      default=-1,
      dest="version",
      help=("Firmware version that is built."),
  )

  main_parser.set_defaults(features=["with_ctap1", "config_command"])

  # Start parsing to know if we're going to list things or not.
  partial_args, _ = main_parser.parse_known_args()

  # We only need the apps_group if we have a board set
  apps_group = main_parser.add_mutually_exclusive_group(
      required=partial_args.board is not None)
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
      help=("Compiles and installs the store_latency example which prints "
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
