# <img alt="OpenSK logo" src="img/OpenSK.svg" width="200px">

## Installation guide

This document lists required steps to start building your own OpenSK.
OpenSK installation is supported and tested under Linux and macOS.

OpenSK is installed as a native [Wasefire](https://github.com/google/wasefire)
applet.

### Software requirements

In order to compile and flash a working OpenSK firmware, you will need the
following:

- rustup (can be installed with [Rustup](https://rustup.rs/))
- the OpenSSL command line tool (can be installed and configured with the
  `libssl-dev` and `pkg-config` packages on Debian)
- uv and python3 (optional, for sending CTAP commands for configuration, can be
  installed with [uv](https://docs.astral.sh/uv/getting-started/installation/))

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
To keep your storage, use the `--update` flag with the below flash script.

## Features

The applet provides a few customization features (all disabled by default):

- `config-command` recommended, enables the authenticatorConfig CTAP command
- `ctap1` recommended, enables CTAP 1 (the applet always implements CTAP 2)
- `debug` enables logging of the applet's debug messages
- `ed25519` enables support for Ed25519 (the applet always implements ECDSA P-256)
- `fingerprint` enables support for fingerprints (requires a sensor)

We provide a `flash.sh` script to flash the OpenSK applet for each platform.
To customize features, use `--features`. For example, to enable debug prints:

```sh
./flash.sh --features=ctap1,config-command,debug <target>
```

The available targets are listed below.

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

Some applet features only work for some targets, special notes will indicate
when a feature is not supported, or extra steps need to be taken.

In the following sections, we describe platforms that support OpenSK.

### Host

The applet feature `fingerprint` is not supported.

To install, run:

```sh
./flash.sh host
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

- [Nordic nRF52840-DK](boards/nrf52840dk.md) - target: `nrf52840dk`
- [Nordic nRF52840 Dongle](boards/nrf52840_dongle.md) - target: `nrf52840_dongle`
- [Makerdiary nRF52840-MDK USB dongle](boards/nrf52840_mdk.md) - target: `nrf52840_mdk`
- [Feitian OpenSK dongle](boards/nrf52840_feitian.md) - target: `nrf52840_dongle`

### OpenTitan

The applet feature `ed25519` is supported and needs the `ed25519`
platform feature.

The applet feature `fingerprint` is not supported.

#### Board: Teacup A2

A LED (active high) needs to be connected to R10. A capacitive touch needs to be
connected to R13.

```sh
./flash.sh opentitan
```

## Configuring the firmware

After flashing the firmware, you can configure it.
You can use a custom AAGUID, batch attestation key and certificate.
Only perform this step if you understand the privacy implications. Read the
[certificate section in Customization](customization.md#Certificate-considerations)
to find the necessary command.
