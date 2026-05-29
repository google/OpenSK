#!/usr/bin/env bash
# Copyright 2026 Google LLC
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

FEATURES="ctap1,config-command"

usage() {
  echo "Usage: $0 [options] <target>"
  echo ""
  echo "Options:"
  echo "  --features=<features>  Comma-separated list of features to enable (default: $FEATURES)"
  echo "  --update               Update instead of flashing (preserves storage)"
  echo ""
  echo "Targets:"
  echo "  host               Simulated device on host"
  echo "  opentitan          OpenTitan board"
  echo "  nrf52840dk         Nordic nRF52840 Development Kit"
  echo "  nrf52840_dongle    Nordic nRF52840 Dongle"
  echo "  nrf52840_mdk       Makerdiary nRF52840 MDK USB Dongle"
  exit 1
}

CMD=(flash)

while [[ $# -gt 0 ]]; do
  case $1 in
    --features=*)
      FEATURES="${1#*=}"
      shift
      ;;
    --update)
      CMD=(update --both)
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      if [ -z "$TARGET" ]; then
        TARGET=$1
        shift
      else
        echo "Error: Unknown argument $1"
        usage
      fi
      ;;
  esac
done

if [ -z "$TARGET" ]; then
  echo "Error: Target is required."
  usage
fi

# Ensure we are in the root directory of OpenSK
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

WASEFIRE_DIR="third_party/wasefire"

if [ ! -d "$WASEFIRE_DIR" ] || [ -z "$(ls -A "$WASEFIRE_DIR")" ]; then
  echo "$WASEFIRE_DIR is empty or does not exist. Run './setup.sh' first."
  exit 1
fi

cd "$WASEFIRE_DIR"

echo "Flashing target: $TARGET"
echo "With features: $FEATURES"

SOFTWARE_CRYPTO_FEATURES="software-crypto-aes256-cbc"
SOFTWARE_CRYPTO_FEATURES+=",software-crypto-hmac-sha256"
SOFTWARE_CRYPTO_FEATURES+=",software-crypto-p256-ecdh"
SOFTWARE_CRYPTO_FEATURES+=",software-crypto-p256-ecdsa"

case $TARGET in
  host)
    if [ "${CMD[0]}" = "update" ]; then
      cargo xtask --native applet rust ../.. --features="$FEATURES" \
        runner host "${CMD[@]}"
    else
      cargo xtask --native applet rust ../.. --features="$FEATURES" \
        runner host flash --usb-ctap --interface=web
    fi
    ;;
  opentitan)
    cargo xtask --release --native applet rust ../.. --opt-level=z --features="$FEATURES" \
      runner opentitan --opt-level=z --features=usb-ctap \
      "${CMD[@]}"
    ;;
  nrf52840dk)
    cargo xtask --release --native applet rust ../.. --opt-level=z --features="$FEATURES" \
      runner nordic --opt-level=z --features=usb-ctap \
        --features="$SOFTWARE_CRYPTO_FEATURES" \
      "${CMD[@]}"
    ;;
  nrf52840_dongle)
    cargo xtask --release --native applet rust ../.. --opt-level=z --features="$FEATURES" \
      runner nordic --board=dongle --opt-level=z --features=usb-ctap \
        --features="$SOFTWARE_CRYPTO_FEATURES" \
      "${CMD[@]}"
    ;;
  nrf52840_mdk)
    # Ensure led-1 is included for MDK
    MDK_FEATURES="$FEATURES"
    if [[ ! "$MDK_FEATURES" =~ "led-1" ]]; then
      MDK_FEATURES="$MDK_FEATURES,led-1"
    fi
    cargo xtask --release --native applet rust ../.. --opt-level=z --features="$MDK_FEATURES" \
      runner nordic --board=makerdiary --opt-level=z --features=usb-ctap \
        --features="$SOFTWARE_CRYPTO_FEATURES" \
      "${CMD[@]}"
    ;;
  *)
    echo "Error: Unknown target $TARGET"
    usage
    ;;
esac
