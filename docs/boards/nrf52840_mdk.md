# <img alt="OpenSK logo" src="../img/OpenSK.svg" width="200px">

## Nordic nRF52840 MDK

Make sure the
[makerdiary](https://makerdiary.com/products/nrf52840-mdk-usb-dongle-w-case)
is in DFU mode by plugging it while holding the button. The LED should be green.
Also make sure the USB mass storage device class is mounted. It should appear as
UF2BOOT.

```sh
cargo xtask --release --native \
  applet rust ../.. --opt-level=z --features=ctap1,config-command,led-1 \
  runner nordic --board=makerdiary --opt-level=z --features=usb-ctap \
    --features=software-crypto-aes256-cbc,software-crypto-hmac-sha256 \
    --features=software-crypto-p256-ecdsa,software-crypto-p256-ecdh \
  flash
```

### Buttons and LEDs

The big, white button conveys user presence to the application. Some actions
like register and login will make the device blink, asking you to confirm the
transaction with a button press.

The LED shows the state of the app. There are different patterns:

| Pattern                      | Cause                  |
|------------------------------|------------------------|
| Green slow blinking          | Asking for touch       |
| Green fast blinking for 5s   | Wink (just saying Hi!) |
| Red glow                     | Busy                   |
| Green steady light           | DFU mode               |
