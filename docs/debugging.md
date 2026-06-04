# <img alt="OpenSK logo" src="img/OpenSK.svg" width="200px">

## Troubleshooting and Debugging

### Inspecting USB

To check whether your operating system identifies OpenSK over USB:

On Linux, try `lsusb` or `dmesg`.

On macOS, use the `ioreg` tool:

```sh
ioreg -p IOUSB
```

### Debug console

You may need to install extra
[udev rules for probe-rs](https://probe.rs/docs/getting-started/probe-setup/).

To flash a firmware that prints more debugging information, remove `--release`
from the flash command, and add `--log=trace/debug/info/warn/error` with the
level of your choice.

Adding debugging to your firmware increases resource usage, including

* USB communication speed
* RAM usage
* binary size

Depending on your choice of board, this may affect functionality, e.g., cause
packet loss.
