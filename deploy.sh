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


set -e

if [ "x$VERBOSE" != "x" ]
then
  set -x
fi

info_text="$(tput bold)info:$(tput sgr0)"
error_text="$(tput bold)error:$(tput sgr0)"

tab_folder="target/tab"
# elf2tab requires a file named "cortex-m4", so this path is used for all
# target applications.
elf_file_name="${tab_folder}/cortex-m4.elf"

# elf2tab 0.4.0 and below uses "-n" flag but 0.5.0-dev changes that "-p" or
# "--package-name"
# We try to be compatible with both versions.
elf2tab_package_param="-n"
if which elf2tab > /dev/null 2>&1
then
  if [ "$(elf2tab --version | cut -d' ' -f2)" = "0.5.0-dev" ]
  then
    # Short parameter is "-p" but long parameter names should be prefered
    # when they are used in scripts.
    elf2tab_package_param="--package-name"
  fi
else
  echo ""
  echo "Command elf2tab not found. Have you run the setup.sh script?"
  exit 2
fi

# We need to specify the board explicitly to be able to flash after 0x80000.
tockloader_flags=(
  --jlink
  --board="${board:-nrf52840}"
  --arch=cortex-m4
  --jlink-device=nrf52840_xxaa
  --page-size=4096
)

declare -A supported_boards
supported_boards["nrf52840dk"]="Y"
supported_boards["nrf52840_dongle"]="Y"
supported_boards["nrf52840_mdk_usb_dongle"]="Y"

declare -A enabled_features=( [with_ctap1]=Y )

print_usage () {
  cat <<EOH
Usage: $0 [options...] <actions...>

Example:
  In order to install TockOS and a debug version of OpenSK on a Nordic nRF52840-DK
  board, you need to run the following command:
    board=nrf52840dk $0 --panic-console os app_debug

Actions:
  os
    Compiles and installs Tock OS on the selected board.
    The target board must be indicated by setting the environment
    variable \$board

  app
    Compiles and installs OpenSK application.

  app_debug
    Compiles and installs OpenSK application in debug mode (i.e. more debug messages
    will be sent over the console port such as hexdumps of packets)

  crypto_bench
    Compiles and installs the crypto_bench example that tests the performance
    of the cryptographic algorithms on the board.

Options:
  --dont-clear-apps
      When installing an application, previously installed applications won't
      be erased from the board.

  --no-u2f
      Compiles OpenSK application without backward compatible support for
      U2F/CTAP1 protocol.


  --regen-keys
      Forces the generation of src/ctap/key_materials.rs file.
      This won't force re-generate OpenSSL files under crypto_data/ directory.
      If the OpenSSL files needs to be re-generated, simply delete them (or
      the whole directory).

  --panic-console
      In case of application panic, the console will be used to output messages
      before starting blinking the LEDs on the board.

EOH
}

display_supported_boards () {
  echo "$info_text Currently supported boards are:"
  for b in ${!supported_boards[@]}
  do
    if [ -d "third_party/tock/boards/nordic/$b" -a \
         -e "third_party/tock/boards/nordic/$b/Cargo.toml" ]
    then
      echo "  - $b"
    fi
  done
}

# Import generate_crypto_materials function
source tools/gen_key_materials.sh

build_app_padding () {
  # On nRF52840, the MMU can have 8 sub-regions and the flash size is 0x1000000.
  # By default, applications are flashed at 0x30000 which means the maximum size
  # for an application is 0x40000 (an application of size 0x80000 would need 16
  # sub-regions of size 0x10000; sub-regions need to be aligned on their size).
  # This padding permits to have the application start at 0x40000 and increase
  # the maximum application size to 0x80000 (with 4 sub-regions of size
  # 0x40000).
  (
    # Version: 2
    echo -n "0200"
    # Header size: 0x10
    echo -n "1000"
    # Total size: 0x10000
    echo -n "00000100"
    # Flags: 0
    echo -n "00000000"
    # Checksum
    echo -n "02001100"
  ) | xxd -p -r > "${tab_folder}/padding.bin"
}

build_app () {
  # Flatten the array
  # This is equivalent to the following python snippet: ' '.join(arr).replace(' ', ',')
  local feature_list=$(IFS=$'\n'; echo "$@")
  if [ "X${feature_list}" != "X" ]
  then
    feature_list="${feature_list// /,}"
  fi

  cargo build \
    --release \
    --target=thumbv7em-none-eabi \
    --features="${feature_list}"

  mkdir -p "target/tab"
  cp "target/thumbv7em-none-eabi/release/ctap2" "$elf_file_name"

  elf2tab \
    "${elf2tab_package_param}" "ctap2" \
    -o "${tab_folder}/ctap2.tab" \
    "$elf_file_name" \
    --stack 16384 \
    --app-heap 90000 \
    --kernel-heap 1024 \
    --protected-region-size=64
}

build_crypto_bench () {
  cargo build \
    --release \
    --target=thumbv7em-none-eabi \
    --example crypto_bench

  mkdir -p "target/tab"
  cp "target/thumbv7em-none-eabi/release/examples/crypto_bench" "$elf_file_name"

  elf2tab \
    "${elf2tab_package_param}" "crypto_bench" \
    -o "${tab_folder}/crypto_bench.tab" \
    "$elf_file_name" \
    --stack 16384 \
    --app-heap 90000 \
    --kernel-heap 1024 \
    --protected-region-size=64
}

deploy_tock () {
  if [ "x$board" = "x" ];
  then
    echo "$error_text You must set the board in order to install Tock OS (example: \`board=nrf52840dk $0 os\`)"
    display_supported_boards
    return 1
  fi
  if [ "${supported_boards[$board]+x}" = "x" -a -d "third_party/tock/boards/nordic/$board" ]
  then
    make -C third_party/tock/boards/nordic/$board flash
  else
    echo "$error_text The board '$board' doesn't seem to be supported"
    display_supported_boards
    return 1
  fi
}

clear_apps=Y
install_os=N
install_app=none

force_generate=N
has_errors=N

if [ "$#" -eq "0" ]
then
  print_usage
  exit 1
fi

while [ "$#" -ge "1" ]
do
  case "$1" in
    --dont-clear-apps)
      clear_apps=N
    ;;

    --no-u2f)
      unset enabled_features["with_ctap1"]
    ;;

    --regen-keys)
      force_generate=Y
    ;;

    --panic-console)
      enabled_features["panic_console"]="Y"
    ;;

    os)
      install_os=Y
    ;;

    app)
      install_app=ctap2
    ;;

    app_debug)
      install_app=ctap2
      enabled_features["debug_ctap"]="Y"
    ;;

    crypto_bench)
      install_app=crypto_bench
    ;;

    *)
      echo "$error_text Unsupported option: '"$1"'"
      has_errors=Y
    ;;
  esac
  shift 1
done

if [ "$has_errors" = "Y" ]
then
  echo ""
  print_usage
  exit 1
fi

# Test if we need to update Rust toolchain
# rustc --version outputs a version line such as:
# rustc 1.40.0-nightly (0e8a4b441 2019-10-16)
# The sed regexp turns it into:
# nightly-2019-10-16
current_toolchain=$(rustc --version | sed -e 's/^rustc [0-9]*\.[0-9]*\.[0-9]*-\(nightly\) ([0-9a-f]* \([0-9]*-[0-9]*-[0-9]*\))$/\1-\2/')
target_toolchain=$(head -n 1 rust-toolchain)

if [ "x${current_toolchain}" != "x${target_toolchain}" ]
then
  rustup install "${target_toolchain}"
  rustup target add thumbv7em-none-eabi
fi

if [ "$install_os" = "Y" ]
then
  deploy_tock
fi

# Don't try to uninstall app if we don't plan to install after.
if [ "$install_app" != "none" -a "$clear_apps" = "Y" ]
then
  # Uninstall can fail if there's no app already installed.
  # This is fine and we don't want that to stop the script
  tockloader uninstall "${tockloader_flags[@]}" -a 0x40000 || true
fi

if [ "$install_app" = "ctap2" ]
then
  generate_crypto_materials "${force_generate}"
  build_app "${!enabled_features[@]}"
fi

if [ "$install_app" = "crypto_bench" ]
then
  build_crypto_bench
fi

if [ "$install_app" != "none" ]
then
  build_app_padding
  tockloader flash "${tockloader_flags[@]}" -a 0x30000 "${tab_folder}/padding.bin"
  tockloader install "${tockloader_flags[@]}" -a 0x40000 "${tab_folder}/${install_app}.tab"
fi
