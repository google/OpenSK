# <img alt="OpenSK logo" src="../img/OpenSK.svg" width="200px">

## Nordic nRF52840 Dongle

![Nordic dongle](../img/dongle_front.jpg)

### 3D printed enclosure

To protect and carry your key, we partnered with a professional designer and we
are providing a custom enclosure that can be printed on both professional 3D
printers and hobbyist models.

![OpenSK Enclosure](../img/enclosure.jpg)

All the required files can be downloaded from
[Thingiverse](https://www.thingiverse.com/thing:4132768) including the STEP
file, allowing you to easily make the modifications you need to further
customize it.

### Flashing using DFU (preferred method)

You need `nrfutil` version 6. The [install manual](../install.md) has
setup instructions.

To flash the firmware, run:

```shell
./deploy.py --board=nrf52840_dongle_dfu --opensk --programmer=nordicdfu
```

The script will ask you to switch to DFU mode. To activate that on your dongle,
keep the button pressed while inserting the device into your USB port. You may
additionally need to press the tiny, sideways facing reset button. The device
indicates DFU mode with a slowly blinking red LED.

### Flashing with an external programmer (JLink, OpenOCD, etc.)

If you want to use JTAG with the dongle, you need additional hardware.

*   a [Segger J-Link](https://www.segger.com/products/debug-probes/j-link/) JTAG
    probe.
*   a
    [TC2050 Tag-Connect programming cable](https://www.tag-connect.com/product/tc2050-idc-nl-10-pin-no-legs-cable-with-ribbon-connector).
*   a [Tag-Connect TC2050 ARM2010](http://www.tag-connect.com/TC2050-ARM2010)
    adaptor
*   optionally a
    [Tag-Connect TC2050 retainer clip](http://www.tag-connect.com/TC2050-CLIP)
    to keep the spring loaded connector pressed to the PCB.

Follow these steps:

1.  The JTAG probe used for programming won't provide power to the board.
    Therefore you will need to use a USB-A extension cable to power the dongle
    through its USB port.

1.  Connect the TC2050 cable to the pads below the PCB:

    ![Nordic dongle pads](../img/dongle_pads.jpg)

1.  You can use the retainer clip if you have one to avoid maintaining pressure
    between the board and the cable:

    ![Nordic dongle retainer clip](../img/dongle_clip.jpg)

#### JLink

Run our script for compiling/flashing Tock OS on your device:

```shell
$ ./deploy.py --board=nrf52840_dongle --programmer=jlink
```

#### OpenOCD

1.  Create your openocd config, named `nordic_nrf52840_dongle.cfg` in the
    appropriate location:
    ```shell
    mkdir -p ${HOME}/.openocd/board
    touch ${HOME}/.openocd/board/nordic_nrf52840_dongle.cfg
    ```
    
    Paste the following st-link example and edit the specific setup to your needs:
    ```
    # Specific setup
    source [find interface/stlink-dap.cfg]
    transport select dapdirect_swd
    
    # The rest should be kept the same
    set CHIPNAME nrf52840
    source [find target/nrf52.cfg]
    ```

1.  Test your config:
       
    ```shell
    openocd -f board/nordic_nrf52840_dongle.cfg
    ``` 

1.  Run the deploy script with the appropriate options, i.e.:

    ```shell
    ./deploy.py --board=nrf52840_dongle --opensk --programmer=openocd
    ```


Finally, remove the programming cable and the USB-A extension cable.

### Buttons and LEDs

The bigger, white button conveys user presence to the application. Some actions
like register and login will make the dongle blink, asking you to confirm the
transaction with a button press. The small, sideways pointing buttong next to it
restarts the dongle.

The 2 LEDs show the state of the app. There are different patterns:

| Pattern                            | Cause                  |
|------------------------------------|------------------------|
| all LEDs and colors                | app panic              |
| green and blue blinking            | asking for touch       |
| all LEDs and colors for 5s         | wink (just saying Hi!) |
| red slow blink                     | DFU mode               |
