Platform-Specific Instructions: nRF52840-DK, partition A
===================================

This is an upgrade partition for the adapted nrf52840dk in `../nrf52840dk_opensk`.

Compared to our regular board definition for the nrf52840dk, changes are:
- a `layout.ld` with 128 kB for kernel and app
- the matching kernel address in the `Makefile`
- different `StorageLocation`s in `build.rs`

For everything else, please check the README in `../nrf52840dk_opensk`.
