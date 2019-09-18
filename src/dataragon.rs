extern crate map_in_place;

use map_in_place::MapVecInPlace;

use crate::ecc::encode_with_ecc;
use crate::objects::{CryptoSecretbox, StoredData};
use crate::serialization::paranoid_checksum;
use crate::shamir::create_data_shares;
use shamirsecretsharing::hazmat::{combine_keyshares, create_keyshares};

pub fn split(text: &[u8], allowed_data_damage_level: f32, count: u8, threshold: u8) -> (Vec<Vec<u8>>, CryptoSecretbox) {
    // todo remove this method from 2 lines?
    let (shares, secret_box) = create_data_shares(&text[..], count, threshold);
    return (add_ecc_and_crc(shares, allowed_data_damage_level), secret_box);
}

pub fn add_ecc_and_crc(shares: Vec<Vec<u8>>, allowed_data_damage_level: f32) -> Vec<Vec<u8>> {
    return shares.map(|share| {
        let ecc_len = share.len() * (2 as f32 * allowed_data_damage_level) as usize;
        let encoded = encode_with_ecc(share.as_slice(), ecc_len);

        let format_version: u8 = 0;

        let stored = StoredData {
            version: 0,
            crc_algorithm: 0,
            crc: Vec::from(&paranoid_checksum(share.as_slice()).to_be_bytes() as &[u8]),
            ecc_algorithm: 0,
            ecc: Vec::from(encoded.ecc()),
            encrypted_algorithm: 0,
            data: Vec::from(encoded.data()),
        };

        return bincode::serialize(&stored).unwrap();
    });
}

// todo realize
//pub fn try_to_read_shards_with_crc_and_ecc(stored_shares: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
//
//}

// todo realize
//pub fn restore(text: Vec<&[u8]>, secret_box: CryptoSecretbox) {
//    let decoded: StoredData = bincode::deserialize(&encoded[..]).unwrap();
//}