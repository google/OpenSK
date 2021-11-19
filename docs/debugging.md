# <img alt="OpenSK logo" src="img/OpenSK.svg" width="200px">

## Troubleshooting and Debugging

### Inspecting USB

The following commands should help you identify whether your operating system
identifies OpenSK over USB.

#### Linux

When plugging in the USB key, the following line should appear in `lsusb`.

```shell
$ lsusb
...
Bus XXX Device YYY: ID 1915:521f Nordic Semiconductor ASA OpenSK
```

You should also see lines similar to the following in `dmesg`.

```shell
$ dmesg
...
[XXX] usb A-BB: new full-speed USB device number 00 using xhci_hcd
[XXX] usb A-BB: New USB device found, idVendor=1915, idProduct=521f, bcdDevice= 0.01
[XXX] usb A-BB: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[XXX] usb A-BB: Product: OpenSK
[XXX] usb A-BB: Manufacturer: Nordic Semiconductor ASA
[XXX] usb A-BB: SerialNumber: v0.1
[XXX] hid-generic 0000:0000:0000.0000: hiddev0,hidraw0: USB HID v1.10 Device [Nordic Semiconductor ASA OpenSK] on usb-0000:00:00.0-00/input0
```

#### Mac OS X

When plugging in the USB key, you should see a similar line by using the `ioreg`
tool:

```shell
$ ioreg -p IOUSB
+-o Root  <class IORegistryEntry, id 0x100000100, retain 21>
...
  +-o AppleUSBXHCI Root Hub Simulation@14000000  <class AppleUSBRootHubDevice, id 0x100000a00, registered, matched, active, busy 0 (0 ms), retain 9>
    +-o OpenSK@14400000  <class AppleUSBDevice, id 0x100003c04, registered, matched, active, busy 0 (0 ms), retain 13>
```

### Debug console

On the dev board, you can read the debug messages using JLink. Use one terminal
for the server and one for the client:

```shell
# Terminal 1
JLinkExe -device nrf52 -if swd -speed 1000 -autoconnect 1
# Terminal 2
JLinkRTTClient
```

You can enhance the debug output by adding flags to the deploy command (see
below for details):

*   `--debug`: more debug messages
*   `--panic-console`: add panic messages
*   `--debug-allocations`: print information about the used heap

Adding debugging to your firmware increases resource usage, including

*   USB communication speed
*   RAM usage
*   binary size

Depending on your choice of board, you may have to increase the available stack
for kernel or app, or disable features so that the binary fits the flash. Also
expect more packet loss.

### App panic messages

By default, libtock-rs blinks some LEDs when the userspace application panics.
This is not always convenient as the panic message is lost. In order to enable
a custom panic handler that first writes the panic message via Tock's console
driver, before faulting the app, you can use the `--panic-console` flag of the
`deploy.py` script.

```shell
# Example on Nordic nRF52840-DK board
./deploy.py --board=nrf52840dk --opensk --panic-console
```

### Memory allocations

You may want to track memory allocations to understand the heap usage of
OpenSK. This can be useful if you plan to port it to a board with fewer
available RAM for example. To do so, you can enable the `--debug-allocations`
flag of the `deploy.py` script. This enables a custom (userspace) allocator
that prints a message to the console for each allocation and deallocation
operation.

The additional output looks like the following.

```text
# Allocation of 256 byte(s), aligned on 1 byte(s). The allocated address is
# 0x2002401c. After this operation, 2 pointers have been allocated, totalling
# 384 bytes (the total heap usage may be larger, due to alignment and
# fragmentation of allocations within the heap).
alloc[256, 1] = 0x2002401c (2 ptrs, 384 bytes)
# Deallocation of 64 byte(s), aligned on 1 byte(s), from address 0x2002410c.
# After this operation, 1 pointers are allocated, totalling 512 bytes.
dealloc[64, 1] = 0x2002410c (1 ptrs, 512 bytes)
```

A tool is provided to analyze such reports, in `tools/heapviz`. This tool
parses the console output, identifies the lines corresponding to (de)allocation
operations, and first computes some statistics:

*   Address range used by the heap over this run of the program,
*   Peak heap usage (how many useful bytes are allocated),
*   Peak heap consumption (how many bytes are used by the heap, including
    unavailable bytes between allocated blocks, due to alignment constraints and
    memory fragmentation),
*   Fragmentation overhead (difference between heap consumption and usage).

Then, the `heapviz` tool displays an animated "movie" of the allocated bytes in
heap memory. Each frame in this "movie" shows bytes that are currently
allocated, that were allocated but are now freed, and that have never been
allocated. A new frame is generated for each (de)allocation operation. This tool
uses the `ncurses` library, that you may have to install beforehand.

You can control the tool with the following parameters:

*   `--logfile` (required) to provide the file which contains the console output
    to parse,
*   `--fps` (optional) to customize the number of frames per second in the movie
    animation.

```shell
cargo run --manifest-path tools/heapviz/Cargo.toml -- --logfile console.log --fps 50
```
