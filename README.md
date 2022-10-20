# <img alt="OpenSK logo" src="docs/img/OpenSK.svg" width="200px">

## OpenSK

This is an OpenSK fork that allows signing with a PQC Hybrid scheme. If you are looking for the original documentation, please check the
[develop branch of its GitHub page](https://github.com/google/OpenSK/tree/develop).

## Hardware

You will need a
[Nordic nRF52840-DK](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-DK)
development kit.

## Installation

To install OpenSK,

1.  follow the [general setup steps](docs/install.md),
1.  then continue with the instructions for your specific hardware:
	[Nordic nRF52840-DK](docs/boards/nrf52840dk.md)

## PQC Experiments

### Modes

The Dilithium mode is set at compile time. If you want to perform experiments for different modes,
you will need to recompile. The mode is a feature, defined in
`third_party/dilithium/Cargo.toml`. By default, it is set to
`default = [ "dilithium5", "optimize_stack" ]`. You can change the default mode by either changing
the number 5 to 2 or 3. Or you remove the feature for stack optimizations, e.g.
`default = [ "dilithium2" ]`.

Note that some benchmarks will not run in all modes without stack optimizations. You can try to
play with the stack size in these cases. As an example, stack painting for speed mode Dilithium2
works if you apply the following changes:

*   `APP_HEAP_SIZE = 16384` in `deploy.py`
*   `libtock_core::stack_size! {0x1A000}` in `examples/measure_stack.rs`
*   `STACK_SIZE = 106496;` in `nrf52840_layout.ld`
*   Change the app break from `70 * 1024` to `104 * 1024` in `patches/tock/07-app-break-fix.patch`.

For your convenience, you can also simply try:

```
git apply increase_stack.patch
```

### Compiler flags

To trade binary size for speed, you can play with `[profile.release]` in `Cargo.toml`.
For example, try a different compiler optimization level:

```
opt-level = 3
```

### Debug output

Only the CTAP commands tests are measured end to end on the host. All other experiments are
measured on the embedded device itself and output over RTT. You can either use a client to print
results by running the following commands in different terminals:

```
JLinkExe -device nrf52 -if swd -speed 1000 -autoconnect 1
JLinkRTTClient
```

Or you directly output all messages to a file:

```
JLinkRTTLogger -device NRF52840_XXAA -if swd -speed 1000 -RTTchannel 0
```

### Perform Experiments

The paper contains the following experiments:

#### Crypto benchmarks

Deploy the `crypto_bench` example and read the debug output with one of the methods above:

```
./deploy.py --board=nrf52840dk_opensk --crypto_bench
```

#### CTAP benchmarks

To measure the speed of FIDO commands, run:

```
python benchmarks.py --runs=2000
```

Aggregate results will be printed, and the raw data is written to `make_durations.txt` and
`get_durations.txt`.


#### Stack painting

Deploy the `measure_stack` example and read the debug output with one of the methods above:

```
./deploy.py --board=nrf52840dk_opensk --measure_stack
```

#### x86 benchmarks

You don't need your embedded hardware for those, run:

```
cd third_party/dilithium/
cargo bench --features std
```

