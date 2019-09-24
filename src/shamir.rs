extern crate base58;
extern crate chacha20_poly1305_aead;
extern crate map_in_place;
extern crate rand;
extern crate shamirsecretsharing;

use map_in_place::MapVecInPlace;
use shamirsecretsharing::hazmat::{combine_keyshares, create_keyshares};

use crate::objects::CryptoSecretbox;
use crate::error::*;

pub fn create_data_shares(data: &[u8], count: u8, threshold: u8) -> Result<(Vec<Vec<u8>>, CryptoSecretbox)> {
    // Generate an ephemeral key
    let ref key = rand::random::<[u8; 32]>();

    // Encrypt the text using the key
    let result = aead_wrap(key, data)
        .and_then(|boxed|
            // Share the key using `create_keyshares`
            create_keyshares(key, count, threshold)
                .map(|keyshares| (keyshares, boxed)).map_err(|ssse| ErrorKind::ShamirsSecretSharingEncryptionError(ssse).into()));

    return result;
}

pub fn restore_data_shared(shares: Vec<Vec<u8>>, b: CryptoSecretbox) -> Result<Vec<u8>> {
    // Recover the key using `combine_keyshares`
    combine_keyshares(&shares).map(|key|
        // Decrypt the secret message using the restored key
        aead_unwrap(&key, b)).map_err(|e| ErrorKind::ShamirsSecretSharingDecryptionError(e).into() )
}

/// AEAD encrypt the message with `key`
fn aead_wrap(key: &[u8], text: &[u8]) -> Result<CryptoSecretbox> {
    let nonce = vec![0; 12];
    let mut ciphertext = Vec::with_capacity(text.len());
    chacha20_poly1305_aead::encrypt(&key, &nonce, &[], text, &mut ciphertext)
        .map(|c| c.to_vec())
        .map(|tag| CryptoSecretbox { ciphertext, tag })
        .map_err(|e| ErrorKind::AEADEncryptionError(e).into())
}

/// AEAD decrypt the message with `key`
fn aead_unwrap(key: &[u8], boxed: CryptoSecretbox) -> Vec<u8> {
    let CryptoSecretbox { ciphertext, tag } = boxed;
    let nonce = vec![0; 12];
    let mut text = Vec::with_capacity(ciphertext.len());
    chacha20_poly1305_aead::decrypt(&key, &nonce, &[], &ciphertext, &tag, &mut text).unwrap();
    text
}

#[cfg(test)]
mod test {
    use super::*;

//    #[test]
//    fn ecc_works_with_only_ecc_corruption() {
//        let text = "abc".as_bytes();
//        let count = 10;
//        let threshold = 5;
//
//        let (boxed, keyshares) = {
//            // Generate an ephemeral key
//            let ref key = rand::random::<[u8; 32]>();
//
//            // Encrypt the text using the key
//            let boxed = aead_wrap(key, text);
//
//            // Share the key using `create_keyshares`
//            let keyshares = create_keyshares(key, count, threshold).unwrap();
//
//            (boxed, keyshares)
//        };
//
//        let restored = {
//            // Recover the key using `combine_keyshares`
//            let key = combine_keyshares(&keyshares).unwrap();
//
//            // Decrypt the secret message using the restored key
//            aead_unwrap(&key, boxed)
//        };
//
//        assert_eq!(restored, text);
//    }
}
