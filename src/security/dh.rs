use num_bigint::{BigUint, RandBigInt};
use num_traits::identities::{One, Zero};
use rand_core::CryptoRng;

#[derive(Clone)]
pub struct DHPublicKey {
    pub_key: BigUint,
}

#[derive(Clone)]
pub struct DHPrivateKey {
    params: DHParameters,
    priv_key: BigUint,
}

#[derive(Clone)]
pub struct DHParameters {
    p: BigUint,
    g: BigUint,
}

impl DHPublicKey {
    pub fn new(key: &[u8]) -> DHPublicKey {
        DHPublicKey {
            pub_key: BigUint::from_bytes_be(key),
        }
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.pub_key.to_bytes_be()
    }
}

impl DHPrivateKey {
    pub fn from_random<R: RngCore + CryptoRng>(params: &DHParameters, rng: &mut R) -> DHPrivateKey {
        loop {
            let priv_key = rng.gen_biguint(params.key_length() as u64);
            if !priv_key.is_zero() && !priv_key.is_one() {
                break DHPrivateKey {
                    params: params.clone(),
                    priv_key: priv_key,
                };
            }
        }
    }

    pub fn public_key(&self) -> DHPublicKey {
        let pub_key = self.params.g.modpow(&self.priv_key, &self.params.p);
        DHPublicKey { pub_key: pub_key }
    }

    pub fn exchange(&self, pub_key: &DHPublicKey) -> BigUint {
        pub_key.pub_key.modpow(&self.priv_key, &self.params.p)
    }
}

impl DHParameters {
    pub fn new(p: &[u8], g: u64) -> DHParameters {
        DHParameters {
            p: BigUint::from_bytes_be(p),
            g: BigUint::from(g),
        }
    }

    pub fn key_length(&self) -> u64 {
        self.p.bits()
    }
}
