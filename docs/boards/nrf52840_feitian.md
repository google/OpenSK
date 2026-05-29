# <img alt="OpenSK logo" src="../img/OpenSK.svg" width="200px">

## Feitian OpenSK USB Dongle

### Flashing

This board is similar in hardware to the Nordic nRF52840 Dongle. You can use DFU
to flash it, instructions to enter DFU mode depend on the version of your
hardware. See
[Feitian's instructions](https://feitiantech.github.io/OpenSK_USB/). In short:

- In V1, use a paperclip to press the Reset button through the tiny hole.
- In V2, push and hold the user button for more than 10 seconds after
  connecting your device.

Afterwards, you can flash your Feitian OpenSK by running:

```sh
./flash.sh nrf52840_dongle
```

Note: Using `nrf52840_dongle` is not a typo. They use similar hardware.

### Buttons and LEDs

For both hardware versions, the buttons and LEDs are described in detail in the
[hardware section](https://feitiantech.github.io/OpenSK_USB/hardware/) of
Feitian's website.
