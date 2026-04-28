# <img alt="OpenSK logo" src="img/OpenSK.svg" width="200px">

## Installation guide

This document lists required steps to start build your own OpenSK.

OpenSK is installed as a native [Wasefire](https://github.com/google/wasefire)
applet.

### Software requirements

In order to compile and flash a working OpenSK firmware, you will need the
following:

- rustup (can be installed with [Rustup](https://rustup.rs/))
- uv (can be installed with
  [uv](https://docs.astral.sh/uv/getting-started/installation/))
- python3 and pip (can be installed with the `python3-pip` package on Debian)
- the OpenSSL command line tool (can be installed and configured with the
  `libssl-dev` and `pkg-config` packages on Debian)

## Setup

Run the setup script and follow install instructions for `rustup` and `uv`, if
necessary.

```sh
./setup.sh
```

The setup script is idempotent, so you can always rerun it, either because you
don't remember you've run it or because you just pulled a newer version of the
`main` branch with `git pull`. Rerun it if any command below fails.

If this is the first time installing OpenSK on a Linux host machine, you need to
install a `udev` rule file to allow non-root users to interact with OpenSK
devices. To install it, execute:

```sh
sudo cp rules.d/99-wasefire.rules /etc/udev/rules.d/
sudo udevadm control --reload
```

## Storage

OpenSK stores data in the devices flash storage, for example your credentials.
When you flash Wasefire, you will erase that storage.

If you flash Wasefire and OpenSK for the second time, and want to keep your
storage, replace `flash` in the below commands with `update --both`.

## Features

The applet provides a few customization features (all disabled by default):

- `config-command` recommended, enables the authenticatorConfig CTAP command
- `ctap1` recommended, enables CTAP 1 (the applet always implements CTAP 2)
- `debug` enables logging of the applet's debug messages
- `ed25519` enables support for Ed25519 (the applet always implements ECDSA P-256)
- `fingerprint` enables support for fingerprints (requires a sensor)

The hardware specific commands below to flash a firmware contain the default
argument `--features=ctap1,config-command`. Add or remove features there.

## Platforms

The applet needs the platform to implement the following features of the board API:

- `api-button`
- `api-clock`
- `api-crypto-aes256-cbc`
- `api-crypto-ed25519` if the applet `ed25519` feature is enabled
- `api-crypto-hmac-sha256`
- `api-crypto-p256-ecdh`
- `api-crypto-p256-ecdsa`
- `api-crypto-sha256`
- `api-fingerprint-matcher` if the applet `fingerprint` feature is enabled
- `api-led`
- `api-rng`
- `api-storage`
- `api-timer`
- `api-usb-ctap`

Run commands below from the directory `third_party/wasefire/`.
They contain the necessary platform features. If you want to use applet
features like `fingerprint`, you may need to add the corresponding platform
feature. Set them using `--features=` prefix for the `runner`.
Some applet features only work for some targets, special notes will indicate
when a feature is not supported, or extra steps need to be taken.

In the following sections, we provide instructions to flash an OpenSK applet for
each platform provided by this repository.

### Host

The applet feature `fingerprint` is not supported.

To install, run:

```sh
cargo xtask --native applet rust ../.. --features=ctap1,config-command \
  runner host flash --usb-ctap --interface=web
```

### nRF52840

The applet feature `ed25519` is not supported.

The applet feature `fingerprint` is supported for the development kit if an [FPC
2534](https://www.fingerprints.com/solutions/access/fpc-allkey-development-kit)
is connected to the board. In that case, the `fpc2534` platform feature must be
enabled.

An FPC 2532 should theoretically also be supported (but has not been tested)
using the same platform feature.

#### Boards

For more details on the boards, see:

- [Nordic nRF52840-DK](docs/boards/nrf52840dk.md)
- [Nordic nRF52840 Dongle](docs/boards/nrf52840_dongle.md)
- [Makerdiary nRF52840-MDK USB dongle](docs/boards/nrf52840_mdk.md)
- [Feitian OpenSK dongle](docs/boards/nrf52840_feitian.md)

### OpenTitan

The applet feature `ed25519` is supported and needs the `ed25519`
platform feature.

The applet feature `fingerprint` is not supported.

#### Board: Teacup A2

A LED (active high) needs to be connected to R10. A capacitive touch needs to be
connected to R13.

```sh
cargo xtask --release --native \
  applet rust ../.. --opt-level=z --features=ctap1,config-command \
  runner opentitan --opt-level=z --features=usb-ctap \
  flash
```
