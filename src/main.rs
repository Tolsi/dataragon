use shamirsecretsharing::*;

use structopt::StructOpt;

extern crate chacha20_poly1305_aead;
extern crate rand;
extern crate shamirsecretsharing;
use base58::ToBase58;

use chacha20_poly1305_aead::{encrypt, decrypt};
use shamirsecretsharing::hazmat::{create_keyshares, combine_keyshares};

/// Secret sharing params.
#[derive(StructOpt)]
struct SharingParams {
    /// The pattern to look for
    #[structopt(short = "c", long = "count")]
    /// Minimal number of parts to recover the secret.
    ///
    /// Blah blah blah shamir's secret sharing scheme blah blah
    c: u8,
    #[structopt(short = "t", long = "threshold")]
    t: u8,
    #[structopt(short = "s", long = "secret")]
    secret: String
}

/// Stores an encrypted message with a message authentication tag
struct CryptoSecretbox {
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

/// AEAD encrypt the message with `key`
fn aead_wrap(key: &[u8], text: &[u8]) -> CryptoSecretbox {
    let nonce = vec![0; 12];
    let mut ciphertext = Vec::with_capacity(text.len());
    let tag = encrypt(&key, &nonce, &[], text, &mut ciphertext).unwrap().to_vec();
    CryptoSecretbox { ciphertext: ciphertext, tag: tag }
}

/// AEAD decrypt the message with `key`
fn aead_unwrap(key: &[u8], boxed: CryptoSecretbox) -> Vec<u8> {
    let CryptoSecretbox { ciphertext: ciphertext, tag: tag } = boxed;
    let nonce = vec![0; 12];
    let mut text = Vec::with_capacity(ciphertext.len());
    decrypt(&key, &nonce, &[], &ciphertext, &tag, &mut text).unwrap();
    text
}

fn main() {
    let args = SharingParams::from_args();

    // Create a some shares over the secret data `[42, 42, 42, ...]`
    let text = args.secret.as_bytes();
    let count = args.c;
    let threshold = args.t;

    let (boxed, keyshares) = {
        // Generate an ephemeral key
        let ref key = rand::random::<[u8; 32]>();

        // Encrypt the text using the key
        let boxed = aead_wrap(key, text);

        // Share the key using `create_keyshares`
        let keyshares = create_keyshares(key, count, threshold).unwrap();

        (boxed, keyshares)
    };

    for share in keyshares.iter() {
        println!("Share: {:?}", share.as_slice().to_base58());
    }

    let restored = {
        // Recover the key using `combine_keyshares`
        let key = combine_keyshares(&keyshares).unwrap();

        // Decrypt the secret message using the restored key
        aead_unwrap(&key, boxed)
    };

    assert_eq!(restored, text);
}
