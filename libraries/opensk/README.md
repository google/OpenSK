# OpenSK library

[![Crate]][crates.io]
[![Documentation]][docs.rs]
[![License]][LICENSE-APACHE]

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

[Apache-2.0][LICENSE-APACHE].

[crates.io]: https://crates.io/crates/opensk
[Crate]: https://img.shields.io/crates/v/opensk
[docs.rs]: https://docs.rs/opensk
[Documentation]: https://docs.rs/opensk/badge.svg
[License]: https://img.shields.io/crates/l/opensk
[LICENSE-APACHE]: https://github.com/google/OpenSK/blob/develop/LICENSE
