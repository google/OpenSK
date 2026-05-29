# <img alt="OpenSK logo" src="../img/OpenSK.svg" width="200px">

## Nordic nRF52840 MDK

Make sure the
[makerdiary](https://makerdiary.com/products/nrf52840-mdk-usb-dongle-w-case)
is in DFU mode by plugging it while holding the button. The LED should be green.
Also make sure the USB mass storage device class is mounted. It should appear as
UF2BOOT.

```sh
./flash.sh nrf52840_mdk
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
