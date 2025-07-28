# <img alt="OpenSK logo" src="img/OpenSK.svg" width="200px">

## Installation guide

This document lists required steps to start build your own OpenSK.

### Programmers

OpenSK supports different ways to flash your board:

* [Segger J-Link](https://www.segger.com/products/debug-probes/j-link/)
  (default method).
* [OpenOCD](http://openocd.org/).
* [pyOCD](https://pypi.org/project/pyocd/).
* [nrfutil](https://pypi.org/project/nrfutil/) for the USB dongle boards that
  support it, which allows you to directly flash a working board over USB
  without additional hardware.

### Software requirements

In order to compile and flash a working OpenSK firmware, you will need the
following:

* rustup (can be installed with [Rustup](https://rustup.rs/))
* python3 and pip (can be installed with the `python3-pip` package on Debian)
* the OpenSSL command line tool (can be installed and configured with the
  `libssl-dev` and `pkg-config` packages on Debian)
* `nrfutil` (pip package of the same name), if you want to flash
  a device with DFU. Read the disclaimer below.
* `uuid-runtime` if you are missing the `uuidgen` command.
* `llvm` and `gcc-arm-none-eabi` if you want to use the upgradability feature.

The proprietary software to use the default programmer can be found on the
[Segger website](https://www.segger.com/downloads/jlink). Please follow their
instructions to appropriate binaries for your system.

The scripts provided in this project have been tested under Linux and OS X. We
haven't tested them on Windows and other platforms.

You need `nrfutil` version 6, if you want to flash over DFU.
The tool doesn't support Python newer than 3.10. Therefore, we don't officially
support DFU for other versions. If you want to try regardless,
[Nordic's new tool](https://www.nordicsemi.com/Products/Development-tools/nrf-util)
might work for you.

### Compiling the firmware

After cloning or pulling, from inside the OpenSK repository, first we make sure
all patches are installed correctly.
As a developer, skip this step after the initial setup and instead use the
script `maintainers/patches` when necessary.

```shell
# Warning for developers: resets uncommited changes.
./reset.sh
./setup.sh
```

The setup script performs the following steps:

1. Make sure that the git submodules are checked out.

1. Apply our patches that haven't yet been merged upstream to both
   [Tock](https://github.com/tock/tock) and
   [libtock-rs](https://github.com/tock/libtock-rs).

1. Generate crypto material, see [Customization](customization.md) for details.

1. Install the correct Rust toolchain for ARM devices.

1. Install [tockloader](https://github.com/tock/tockloader).

If this is the first time installing OpenSK on a Linux host machine, you need to
install a `udev` rule file to allow non-root users to interact with OpenSK
devices. To install it, execute:

```shell
sudo cp rules.d/55-opensk.rules /etc/udev/rules.d/
sudo udevadm control --reload
```

Then, you need to replug the device for the rule to trigger.

### Erasing your storage

We expect the flash pages for persistent storage to be either blank, or in
OpenSK's storage format.
If you install OpenSK for the first time, or come from an incompatible OpenSK
version, you need to erase your flash before writing the OpenSK firmware.
The develop branch has, and may in the future, introduce breaking changes to the
storage format.

:warning: You will lose logins to all websites that you registered with OpenSK.

To erase your persistent storage, refer to the instructions in
[Flashing a firmware](#flashing-a-firmware) and run the deploy script twice:
first with the `--erase_storage` application parameter, and then as usual with
the `--opensk` application parameter.

### Flashing a firmware

Please follow the instructions for your hardware:

* [Nordic nRF52840-DK](boards/nrf52840dk.md)
* [Nordic nRF52840 Dongle](boards/nrf52840_dongle.md)
* [Makerdiary nRF52840-MDK USB dongle](boards/nrf52840_mdk.md)
* [Feitian OpenSK dongle](boards/nrf52840_feitian.md)

### Configuring the firmware

Last, if you want to use U2F or attestation, configure the certificate. If your
client does not support FIDO2 yet, this step is mandatory for your OpenSK to
work. OpenSK is incompatible with some browsers without a certificate. Please
read the
[certificate section in Customization](customization.md#Certificate-considerations)
for understand privacy tradeoffs.

```shell
./tools/configure.py \
    --certificate=crypto_data/opensk_cert.pem \
    --private-key=crypto_data/opensk.key
```

### Advanced installation

We recommend that you flash your development board with JTAG and dongles with
DFU, as described in the [board documentation](#flashing-a-firmware) linked
above. However, we support other programmers:

* OpenOCD: `./deploy.py --board=nrf52840_dongle_opensk --opensk
  --programmer=openocd`
* pyOCD: `./deploy.py --board=nrf52840_dongle_opensk --opensk
  --programmer=pyocd`
* Custom: `./deploy.py --board=nrf52840_dongle_opensk --opensk
  --programmer=none`. In this case, an IntelHex file will be created and how
  to program a board is left to the user.

If your board is already flashed with Tock OS, you may skip installing it:
`./deploy.py --board=nrf52840dk_opensk --opensk --no-tockos`

For more options, we invite you to read the help of our `deploy.py` script by
running `./deploy.py --help`.

### Upgradability

We experiment with a new CTAP command to allow upgrading your device without
access to its debugging port. For that purpose, the flash storage is split into
4 parts:

* the bootloader to decide with partition to boot
* firmware partition A
* firmware partition B
* the persistent storage for credentials

The storage is backward compatible to non-upgradable boards. Deploying an
upgradable board automatically installs the bootloader. Please keep in mind that
you have to safely store your private signing key for upgrades if you want to
use this feature. For more information on the cryptographic material, see
[Customization](customization.md).

So far, upgradability is only supported for the development board. See the
instructions on the [board specific page](boards/nrf52840dk.md).
