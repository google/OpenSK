extern crate dilithium;
extern crate rng256;

use dilithium::sign::{PubKey, SecKey};
use rng256::Rng256;

const ITERATIONS: u32 = 500;

#[test]
fn test_sk_with_pk() {
    let mut rng = rng256::ThreadRng256 {};
    for _ in 0..ITERATIONS {
        let (sk, pk) = SecKey::gensk_with_pk(&mut rng);
        let pk_from_sk = sk.genpk();
        assert_eq!(pk, pk_from_sk);
    }
}

#[test]
fn test_sign() {
    let mut rng = rng256::ThreadRng256 {};
    for _ in 0..ITERATIONS {
        let sk = SecKey::gensk(&mut rng);

        let mut message = [0; 59];
        rng.fill_bytes(&mut message);
        let sig = sk.sign(&message);

        let pk = sk.genpk();

        let mut bytes = [0; dilithium::params::PK_SIZE_PACKED];
        pk.to_bytes(&mut bytes);
        assert!(pk.verify(&message, &sig));

        message[2] ^= 42;
        assert!(!pk.verify(&message, &sig));
    }
}

#[test]
fn test_seckey_to_bytes_from_bytes() {
    let mut rng = rng256::ThreadRng256 {};

    for _ in 0..ITERATIONS {
        let sk = SecKey::gensk(&mut rng);
        let mut bytes = [0; dilithium::params::SK_SIZE_PACKED];
        sk.to_bytes(&mut bytes);
        let decoded_sk = SecKey::from_bytes(&bytes);
        assert_eq!(decoded_sk, sk);
    }
}

#[test]
fn test_pubkey_to_bytes_from_bytes() {
    let mut rng = rng256::ThreadRng256 {};

    for _ in 0..ITERATIONS {
        let sk = SecKey::gensk(&mut rng);
        let pk = sk.genpk();
        let mut bytes = [0; dilithium::params::PK_SIZE_PACKED];
        pk.to_bytes(&mut bytes);
        let decoded_pk = PubKey::from_bytes(&bytes);
        assert_eq!(decoded_pk, pk);
    }
}
