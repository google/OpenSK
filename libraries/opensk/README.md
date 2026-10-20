# OpenSK library

[![crates.io](https://img.shields.io/crates/v/opensk.svg)](https://crates.io/crates/opensk)
[![docs.rs](https://docs.rs/opensk/badge.svg)](https://docs.rs/opensk)
[![License](https://img.shields.io/crates/l/opensk.svg)](https://crates.io/crates/opensk)

The CTAP2 (FIDO2) authenticator of [OpenSK](https://github.com/google/OpenSK),
as a library: the protocol logic, independent of any board.

The authenticator is parameterized by an environment (the `Env` trait) that
provides storage, randomness, cryptography, user presence and the clock.
OpenSK's firmware implements it for its boards.

With the `std` feature, `env::test::TestEnv` is an environment in memory:
`Ctap::<TestEnv>` runs on a desktop and answers CTAPHID packets
(`process_hid_packet`), for tests of FIDO2 clients without hardware.

## :warning: Disclaimer

This is not an officially supported Google product.

This project is **proof-of-concept and a research platform**. It is **NOT**
meant for a daily usage. See [OpenSK's README](https://github.com/google/OpenSK)
for its status.

## License

Apache-2.0.
