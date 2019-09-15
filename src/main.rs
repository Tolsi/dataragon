use structopt::StructOpt;

extern crate chacha20_poly1305_aead;
extern crate rand;
extern crate shamirsecretsharing;
extern crate reed_solomon;
extern crate sha2;
extern crate crc;

use reed_solomon::{Encoder, Buffer};
use reed_solomon::Decoder;

use base58::ToBase58;

use sha2::{Sha256, Sha512, Digest};
use crc::{crc16, Hasher16};

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
    t: u8
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

fn encode_with_ecc(data: &[u8], ecc_len: usize) -> Buffer {
    // Length of error correction code
    let enc = Encoder::new(ecc_len);
    return enc.encode(&data[..]);
}

fn recover_with_ecc(data: Buffer, ecc_len: usize) -> Buffer {
    // Length of error correction code
    let dec = Decoder::new(ecc_len);
    let known_erasures = None;
    let recovered = dec.correct(&*data, known_erasures).unwrap();
    return recovered;
}

fn print_ecc(data: &[u8]) {
    let ecc_len = data.len() * 2;

    // Encode data
    let encoded = encode_with_ecc(data, ecc_len);

    let orig_str = std::str::from_utf8(data).unwrap();
    println!("message:               {:?}", orig_str);
    println!("original data:         {:?}", data);
    println!("error correction code: {:?}", encoded.ecc());

    // Simulate some transmission errors
    let mut corrupted = encoded;
    for i in data.len()+6..corrupted.len() {
        corrupted[i] = 0x0;
    }

    println!("corrupted:             {:?}", *corrupted);

    // Try to recover data
    let recovered = recover_with_ecc(corrupted, ecc_len);

    let recv_str = std::str::from_utf8(recovered.data()).unwrap();

    println!("repaired:              {:?}", recv_str);
}

fn main() {
    let args = SharingParams::from_args();

    let count = args.c;
    let threshold = args.t;

    let read_result = rpassword::read_password_from_tty(Some("Enter your secret (the input is hidden): "));

    let password = if read_result.is_err() {
        rpassword::prompt_password_stdout("Enter your secret (the input is hidden): ").unwrap()
    } else {
        read_result.unwrap()
    };

    let text = password.as_bytes();

    let crc_bytes = &paranoid_checksum(text).to_be_bytes();
    println!("{:?}", crc_bytes);

    print_ecc(text);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecc_works() {
        let data = "abc".as_bytes();
        let ecc_len = data.len() * 2;

        // Encode data
        let encoded = encode_with_ecc(data, ecc_len);

        // Simulate some transmission errors
        let mut corrupted = encoded;
        for i in data.len()+6..corrupted.len() {
            corrupted[i] = 0x0;
        }

        // Try to recover data
        let recovered = recover_with_ecc(corrupted, ecc_len);

        assert_eq!(data, recovered.data());
    }
}

fn paranoid_checksum(data: &[u8]) -> u16 {
    let mut hasher = Sha512::new();
    hasher.input(data);
    let result = hasher.result();
    return crc16::checksum_usb(result.as_slice());
}