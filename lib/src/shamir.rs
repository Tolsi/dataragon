extern crate chacha20_poly1305_aead;
extern crate map_in_place;
extern crate rand;
extern crate shamirsecretsharing;

use shamirsecretsharing::hazmat::{combine_keyshares, create_keyshares};

use crate::error::*;
use crate::objects::CryptoSecretbox;

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

pub fn combine_data_shares(shares: Vec<Vec<u8>>, b: &CryptoSecretbox) -> Result<Vec<u8>> {
    // Recover the key using `combine_keyshares`
    combine_keyshares(&shares)
        .map_err(|e| ErrorKind::ShamirsSecretSharingDecryptionError(e).into())
        .and_then(|key|
            // Decrypt the secret message using the restored key
            aead_unwrap(&key, b))
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
fn aead_unwrap(key: &[u8], boxed: &CryptoSecretbox) -> Result<Vec<u8>> {
    let CryptoSecretbox { ciphertext, tag } = boxed;
    let nonce = vec![0; 12];
    let mut text = Vec::with_capacity(ciphertext.len());
    chacha20_poly1305_aead::decrypt(&key, &nonce, &[], &ciphertext, &tag, &mut text).map(|_| text)
        .map_err(|e| ErrorKind::AEADDecryptionError(e).into())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sss_sharing_and_combining_works() {
        let text = "abc".as_bytes();
        let count = 10;
        let threshold = 5;

        let (boxed, keyshares) = {
            // Generate an ephemeral key
            let ref key = rand::random::<[u8; 32]>();

            // Encrypt the text using the key
            let boxed = aead_wrap(key, text).unwrap();

            // Share the key using `create_keyshares`
            let keyshares = create_keyshares(key, count, threshold).unwrap();

            (boxed, keyshares)
        };

        let combined = {
            // Recover the key using `combine_keyshares`
            let key = combine_keyshares(&keyshares).unwrap();

            // Decrypt the secret message using the restored key
            aead_unwrap(&key, &boxed).unwrap()
        };

        assert_eq!(combined, text);
    }
}
