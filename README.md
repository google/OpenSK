# <img alt="OpenSK logo" src="docs/img/OpenSK.svg" width="200px">

[![Build Status](https://travis-ci.org/google/OpenSK.svg?branch=master)](https://travis-ci.org/google/OpenSK)
![markdownlint](https://github.com/google/OpenSK/workflows/markdownlint/badge.svg?branch=master)
![pylint](https://github.com/google/OpenSK/workflows/pylint/badge.svg?branch=master)
![Cargo check](https://github.com/google/OpenSK/workflows/Cargo%20check/badge.svg?branch=master)
![Cargo format](https://github.com/google/OpenSK/workflows/Cargo%20format/badge.svg?branch=master)

## OpenSK

This repository contains a Rust implementation of a
[FIDO2](https://fidoalliance.org/fido2/) authenticator.

We developed this as a [Tock OS](https://tockos.org) application and it has been
successfully tested on the following boards:

*   [Nordic nRF52840-DK](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-DK)
*   [Nordic nRF52840-dongle](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-Dongle)

## Disclaimer

This project is proof-of-concept and a research platform. It's still under
development and as such comes with a few limitations:

### FIDO2

Although we tested and implemented our firmware based on the published
[CTAP2.0 specifications](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html),
our implementation was not reviewed nor officially tested and doesn't claim to
be FIDO Certified.

### Cryptography

We're currently still in the process on making the
[ARM&reg; CryptoCell-310](https://developer.arm.com/ip-products/security-ip/cryptocell-300-family)
embedded in the
[Nordic nRF52840 chip](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fps_nrf52840%2Fcryptocell.html)
work to get hardware-accelerated cryptography. In the meantime we implemented
the required cryptography algorithms (ECDSA, ECC secp256r1, HMAC-SHA256 and
AES256) in Rust as a placeholder. Those implementations are research-quality
code and haven't been reviewed. They don't provide constant-time guarantees and
are not designed to be resistant against side-channel attacks.

## Installation

For a more detailed guide, please refer to our
[installation guide](docs/install.md).

1.  If you just cloned this repository, run the following script (**Note**: you
    only need to do this once):

    ```shell
    ./setup.sh
    ```

2.  If Tock OS is already installed on your board, move to the next step.
    Otherwise, just run one of the following commands, depending on the board
    you have:

    ```shell
    # Nordic nRF52840-DK board
    ./deploy.py os --board=nrf52840_dk
    # Nordic nRF52840-Dongle
    ./deploy.py os --board=nrf52840_dongle
    ```

3.  Next step is to install/update the OpenSK application on your board
    (**Warning**: it will erase the locally stored credentials). Run:

    ```shell
    ./deploy.py app --opensk
    ```

4.  On Linux, you may want to avoid the need for `root` privileges to interact
    with the key. For that purpose we provide a udev rule file that can be
    installed with the following command:

    ```shell
    sudo cp rules.d/55-opensk.rules /etc/udev/rules.d/ &&
    sudo udevadm control --reload
    ```

### Customization

If you build your own security key, depending on the hardware you use, there are
a few things you can personalize:

1.  If you have multiple buttons, choose the buttons responsible for user
    presence in `main.rs`.
2.  Decide whether you want to use batch attestation. There is a boolean flag in
    `ctap/mod.rs`. It is mandatory for U2F, and you can create your own
    self-signed certificate. The flag is used for FIDO2 and has some privacy
    implications. Please check
    [WebAuthn](https://www.w3.org/TR/webauthn/#attestation) for more
    information.
3.  Decide whether you want to use signature counters. Currently, only global
    signature counters are implemented, as they are the default option for U2F.
    The flag in `ctap/mod.rs` only turns them off for FIDO2. The most privacy
    preserving solution is individual or no signature counters. Again, please
    check [WebAuthn](https://www.w3.org/TR/webauthn/#signature-counter) for
    documentation.
4.  Depending on your available flash storage, choose an appropriate maximum
    number of supported residential keys and number of pages in
    `ctap/storage.rs`.

### 3D printed enclosure

To protect and carry your key, we partnered with a professional designer and we
are providing a custom enclosure that can be printed on both professional 3D
printers and hobbyist models.

All the required files can be downloaded from
[Thingiverse](https://www.thingiverse.com/thing:4132768) including the STEP
file, allowing you to easily make the modifications you need to further
customize it.

## Contributing

See [Contributing.md](docs/contributing.md).
