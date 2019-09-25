extern crate map_in_place;

use map_in_place::MapVecInPlace;
use shamirsecretsharing::hazmat::{combine_keyshares, create_keyshares};

use crate::error::Result;
use crate::objects::CryptoSecretbox;
use crate::serialization::{add_ecc_and_crc, try_to_read_bytes_with_crc_and_ecc};
use crate::serialization::paranoid_checksum;
use crate::shamir::{create_data_shares, restore_data_shared};

pub fn split(text: &[u8], allowed_data_damage_level: f32, count: u8, threshold: u8) -> Result<(Vec<Vec<u8>>, CryptoSecretbox)> {
    return create_data_shares(&text[..], count, threshold).map(|(shares, secret_box)| {
        let shares_with_crc_and_ecc = shares.map(|share| add_ecc_and_crc(share, allowed_data_damage_level));
        return (shares_with_crc_and_ecc, secret_box);
    });
}

pub fn restore(shares: Vec<Vec<u8>>, secret_box: &CryptoSecretbox) -> Result<Vec<u8>> {
    let successfully_restored_shares: Vec<Vec<u8>> = shares.map(|s| try_to_read_bytes_with_crc_and_ecc(s.as_slice())).into_iter()
        .filter_map(Result::ok)
        .collect();

    return restore_data_shared(successfully_restored_shares, secret_box);
}


#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use super::*;

    #[test]
    fn split_and_restore_works_with_any_3_and_more_of_10_shards() {
        let shared_secret = "supersecret";
        let (shards, secretbox) = split(shared_secret.as_bytes(), 1.0, 10, 3).unwrap();
        for n in (1..=10) {
            for shards_by_n in shards.as_slice().to_vec().into_iter().combinations(n) {
                let result = restore(shards_by_n, &secretbox);
                assert_eq!(result.is_ok(), n >= 3);
                if result.is_ok() {
                    let restored_string = String::from_utf8(result.unwrap()).unwrap();
                    assert_eq!(shared_secret, restored_string);
                }
            }
        }
    }
}