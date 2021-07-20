enum Version {
    U2F,
    FIDO2,
}

impl Version {
    fn value(&self) -> &[u8] {
        match *self {
            Version::U2F => b"U2F_V2",
            Version::FIDO2 => b"FIDO_2_0",
        }
    }
}
