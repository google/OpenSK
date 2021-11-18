# <img alt="OpenSK logo" src="../img/OpenSK.svg" width="200px">

## Nordic nRF52840 MDK

Makerdiary has instructions on their [website](https://wiki.makerdiary.com/nrf52840-mdk-usb-dongle/opensk/). They use a custom script to deploy via DFU.

After general setup, you still need these steps:

1.  Create the hexfile with the firmware.

    ```shell
    ./deploy.py --board=nrf52840_mdk_dfu --opensk --programmer=none
    ```

1.  Download the
    [script](https://github.com/makerdiary/nrf52840-mdk-usb-dongle/blob/master/tools/uf2conv.py)
    from Makerdiary's GitHub into the OpenSK repository.

1.  Run the script:

    ```shell
    python3 uf2conv.py -c -f 0xada52840 -o target/opensk.uf2 target/nrf52840_mdk_dfu_merged.hex
    ```

1.  Boot into DFU mode. Keep the user button pressed on your hardware while
    inserting it into a USB slot. You should see a bit of red blinking, and then
    a constant green light.

1.  Your dongle should appear in your normal file browser like other USB sticks.
    Copy the file `target/opensk.uf2` over.

1.  Replug to reboot.

### Buttons and LEDs

The big, white button conveys user presence to the application. Some actions
like register and login will make the device blink, asking you to confirm the
transaction with a button press.

The LED shows the state of the app. There are different patterns:

| Pattern                            | Cause                  |
|------------------------------------|------------------------|
| red glow                           | busy                   |
| red and blue blinking              | asking for touch       |
| red, green, white pattern for 5s   | wink (just saying Hi!) |
| constant green                     | DFU mode               |
