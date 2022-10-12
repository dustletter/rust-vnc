use crate::protocol;
use crate::security::dh::{DHParameters, DHPrivateKey, DHPublicKey};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, BlockSizeUser, KeyInit};
use aes::Aes128;
use md5;
use rand_core::OsRng;
use std::cmp::min;

// http://cafbit.com/entry/apple_remote_desktop_quirks
pub fn apple_auth(username: &str, password: &str,
                  handshake: &protocol::AppleAuthHandshake) -> protocol::AppleAuthResponse {
    let param = DHParameters::new(&handshake.prime, handshake.generator as u64);
    let priv_key = DHPrivateKey::from_random(&param, &mut OsRng);
    let pub_key = priv_key.public_key();
    let secret: [u8; 16] = md5::compute(
        &priv_key
            .exchange(&DHPublicKey::new(&handshake.peer_key))
            .to_bytes_be(),
    )
    .into();

    let mut credentials = [0u8; 128];
    let ul = min(64, username.len());
    credentials[0..ul].copy_from_slice(&username.as_bytes()[0..ul]);
    let pl = min(64, password.len());
    credentials[64..(64 + pl)].copy_from_slice(&password.as_bytes()[0..pl]);

    // yes, we really want ECB mode
    let aes = Aes128::new_from_slice(&secret).expect("aes");
    let blocks = credentials.chunks_exact_mut(Aes128::block_size());
    for block in blocks {
        aes.encrypt_block(GenericArray::from_mut_slice(block));
    }

    protocol::AppleAuthResponse {
        ciphertext: credentials,
        pub_key: pub_key.to_bytes_be(),
    }
}
