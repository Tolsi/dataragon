extern crate map_in_place;

use map_in_place::MapVecInPlace;

use crate::serialization::paranoid_checksum;
use crate::shamir::{create_data_shares, restore_data_shared};
use crate::serialization::{add_ecc_and_crc, try_to_read_shards_with_crc_and_ecc};
use shamirsecretsharing::hazmat::{combine_keyshares, create_keyshares};
use crate::objects::CryptoSecretbox;
use crate::error::Result;

pub fn split(text: &[u8], allowed_data_damage_level: f32, count: u8, threshold: u8) -> Result<(Vec<Vec<u8>>, CryptoSecretbox)> {
    return create_data_shares(&text[..], count, threshold).map(|(shares, secret_box)| {
        let shares_with_crc_and_ecc = shares.map(|share| add_ecc_and_crc(share, allowed_data_damage_level));
        return (shares_with_crc_and_ecc, secret_box)
    });
}

pub fn restore(shares: Vec<&[u8]>, secret_box: CryptoSecretbox) -> Result<Vec<u8>> {
    let successfully_restored_shares: Vec<Vec<u8>> = shares.map(|s| try_to_read_shards_with_crc_and_ecc(s)).into_iter()
        .filter_map(Result::ok)
        .collect();

    return restore_data_shared(successfully_restored_shares, secret_box);
}