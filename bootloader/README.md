# OpenSK Bootloader

This bootloader supports upgradability for OpenSK. Its functionality is to

- check images on A/B partitions,
- boot the most recent valid partition.

## How to use

The bootloader is built and deployed by OpenSK's `deploy.py`. If your board
defines a metadata address, it is detected as an upgradable board and this
bootloader is flashed to memory address 0.

## How to debug

The bootloader prints debug message over RTT when compiled in debug mode. Using
`nrfjprog` for flashing and inspecting memory is recommended for debugging.

```shell
RUSTFLAGS="-C link-arg=-Wl,-Tlink.x -C link-arg=-nostartfiles" \
    cargo build --target thumbv7em-none-eabi
llvm-objcopy -O ihex target/thumbv7em-none-eabi/debug/bootloader \
    target/thumbv7em-none-eabi/debug/bootloader.hex
nrfjprog --program target/thumbv7em-none-eabi/debug/bootloader.hex \
    --sectorerase -f nrf52 --reset
```

To read the debug messages, open two terminals for:

```shell
JLinkRTTLogger -device NRF52840_XXAA -if swd -speed 1000 -RTTchannel 0
JLinkRTTClient
```

The first command also logs the output to a file. The second shows all output in
real time.
