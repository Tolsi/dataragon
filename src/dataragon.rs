extern crate map_in_place;

use map_in_place::MapVecInPlace;

use crate::serialization::paranoid_checksum;
use crate::shamir::create_data_shares;
use crate::serialization::add_ecc_and_crc;
use shamirsecretsharing::hazmat::{combine_keyshares, create_keyshares};
use crate::objects::CryptoSecretbox;

pub fn split(text: &[u8], allowed_data_damage_level: f32, count: u8, threshold: u8) -> (Vec<Vec<u8>>, CryptoSecretbox) {
    // todo remove this method from 2 lines?
    let (shares, secret_box) = create_data_shares(&text[..], count, threshold);
    let shares_with_crc_and_ecc = shares.map(|share| add_ecc_and_crc(share, allowed_data_damage_level));
    return (shares_with_crc_and_ecc, secret_box);
}

// todo realize
//pub fn try_to_read_shards_with_crc_and_ecc(stored_shares: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
//
//}

// todo realize
//pub fn restore(text: Vec<&[u8]>, secret_box: CryptoSecretbox) {
//    let decoded: StoredData = bincode::deserialize(&encoded[..]).unwrap();
//}