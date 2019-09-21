extern crate sha2;
extern crate crc;

use crc::crc16;
use sha2::{Sha512, Digest};
use crate::ecc::encode_with_ecc;
use crate::objects::{CryptoSecretbox, StoredData};

pub fn paranoid_checksum(data: &[u8]) -> u16 {
    let mut hasher = Sha512::new();
    hasher.input(data);
    let result = hasher.result();
    return crc16::checksum_usb(result.as_slice());
}

pub fn add_ecc_and_crc(data: Vec<u8>, allowed_data_damage_level: f32) -> Vec<u8> {
    let ecc_len = data.len() * (2 as f32 * allowed_data_damage_level) as usize;
    let encoded = encode_with_ecc(data.as_slice(), ecc_len);

    let format_version: u8 = 0;

    let stored = StoredData {
        version: 0,
        crc_algorithm: 0,
        crc: Vec::from(&paranoid_checksum(data.as_slice()).to_be_bytes() as &[u8]),
        ecc_algorithm: 0,
        ecc: Vec::from(encoded.ecc()),
        encrypted_algorithm: 0,
        data: Vec::from(encoded.data()),
    };

    return bincode::serialize(&stored).unwrap();
}
