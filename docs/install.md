# <img alt="OpenSK logo" src="img/OpenSK.svg" width="200px">

## Installation guide

This document lists required steps to start build your own OpenSK.

### Programmers

OpenSK supports different ways to flash your board:

*   [Segger J-Link](https://www.segger.com/products/debug-probes/j-link/)
    (default method).
*   [OpenOCD](http://openocd.org/).
*   [pyOCD](https://pypi.org/project/pyocd/).
*   [nrfutil](https://pypi.org/project/nrfutil/) for the USB dongle boards that
    support it, which allows you to directly flash a working board over USB
    without additional hardware.

### Software requirements

In order to compile and flash a working OpenSK firmware, you will need the
following:

*   rustup (can be installed with [Rustup](https://rustup.rs/))
*   python3 and pip (can be installed with the `python3-pip` package on Debian)
*   the OpenSSL command line tool (can be installed and configured with the
    `libssl-dev` and `pkg-config` packages on Debian)
*   `nrfutil` (can be installed using `pip3 install nrfutil`) if you want to flash
    a device with DFU
*   `uuid-runtime` if you are missing the `uuidgen` command.

The proprietary software to use the default programmer can be found on the
[Segger website](https://www.segger.com/downloads/jlink). Please follow their
instructions to appropriate binaries for your system.

The scripts provided in this project have been tested under Linux and OS X. We
haven't tested them on Windows and other platforms.

### Compiling the firmware

If you are switching branches or used an old version of OpenSK before, we have
tools to help you migrate to our develop branch. You find more information on
how to update your setup or reset your storage in its
[install instructions](https://github.com/google/OpenSK/blob/develop/docs/install.md).

To clone and setup the repository for the stable branch, run the following
commands:

```shell
git clone https://github.com/google/OpenSK.git
cd OpenSK
./setup.sh
```

The setup script performs the following steps:

1.  Make sure that the git submodules are checked out.

1.  Apply our patches that haven't yet been merged upstream to both
    [Tock](https://github.com/tock/tock) and
    [libtock-rs](https://github.com/tock/libtock-rs).

1.  Generate crypto material, see [Customization](customization.md) for details.

1.  Install the correct Rust toolchain for ARM devices.

1.  Install [tockloader](https://github.com/tock/tockloader).

Additionally on Linux, you need to install a `udev` rule file to allow non-root
users to interact with OpenSK devices. To install it, execute:

```shell
sudo cp rules.d/55-opensk.rules /etc/udev/rules.d/
sudo udevadm control --reload
```

Then, you need and replug the device for the rule to trigger.

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

### Flashing a firmware

From here on, please follow the instructions for your hardware:

*   [Nordic nRF52840-DK](boards/nrf52840dk.md)
*   [Nordic nRF52840 Dongle](boards/nrf52840_dongle.md)
*   [Makerdiary nRF52840-MDK USB dongle](boards/nrf52840_mdk.md)
*   [Feitian OpenSK dongle](boards/nrf52840_feitian.md)

### Advanced installation

We recommend that you flash your development board with JTAG and dongles with
DFU, as described in the [board documentation](#Flashing-a-firmware) linked
above. However, we support other programmers:

*   OpenOCD: `./deploy.py --board=nrf52840_dongle --opensk --programmer=openocd`
*   pyOCD: `./deploy.py --board=nrf52840_dongle --opensk --programmer=pyocd`
*   Custom: `./deploy.py --board=nrf52840_dongle --opensk --programmer=none`.
    In this case, an IntelHex file will be created and how to program a board is
    left to the user.

If your board is already flashed with Tock OS, you may skip installing it:
`./deploy.py --board=nrf52840dk --opensk --no-tockos`

For more options, we invite you to read the help of our `deploy.py` script by
running `./deploy.py --help`.
