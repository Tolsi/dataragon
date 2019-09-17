extern crate map_in_place;

use map_in_place::MapVecInPlace;

use crate::ecc::encode_with_ecc;
use crate::objects::{CryptoSecretbox, StoredData};
use crate::serialization::paranoid_checksum;
use crate::shamir::create_data_shares;

pub fn split(text: &[u8], allowed_data_damage_level: f32, count: u8, threshold: u8) -> (Vec<Vec<u8>>, CryptoSecretbox) {
    let ecc_len = text.len() * (2 as f32 * allowed_data_damage_level) as usize;
    let encoded = encode_with_ecc(text, ecc_len);

    let format_version: u8 = 0;
    let stored = StoredData {
        crc_algorithm: 0,
        crc: Vec::from(&paranoid_checksum(text).to_be_bytes() as &[u8]),
        ecc_algorithm: 0,
        ecc: Vec::from(encoded.ecc()),
        encrypted_algorithm: 0,
        data: Vec::from(encoded.data()),
    };

    let encoded_stored_data: Vec<u8> = bincode::serialize(&stored).unwrap();

    return create_data_shares(&encoded_stored_data[..], count, threshold);
}

// todo
pub fn restore(text: Vec<&[u8]>) {
//    let decoded: StoredData = bincode::deserialize(&encoded[..]).unwrap();
}