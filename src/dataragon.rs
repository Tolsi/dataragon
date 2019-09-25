extern crate map_in_place;

use itertools::Itertools;
use map_in_place::MapVecInPlace;
use shamirsecretsharing::hazmat::{combine_keyshares, create_keyshares};

use crate::error::Result;
use crate::objects::{CryptoSecretbox, StoredData};
use crate::serialization::{add_ecc_and_crc, try_to_read_stored_data};
use crate::serialization::paranoid_checksum;
use crate::shamir::{combine_data_shares, create_data_shares};

pub fn split(text: &[u8], allowed_data_damage_level: f32, count: u8, threshold: u8) -> Result<(Vec<Vec<u8>>, CryptoSecretbox)> {
    return create_data_shares(&text[..], count, threshold).map(|(shares, secret_box)| {
        let shares_with_crc_and_ecc = shares.filter_map(|share| add_ecc_and_crc(share, allowed_data_damage_level).ok());
        return (shares_with_crc_and_ecc, secret_box);
    });
}

pub fn combine(shares: Vec<Vec<u8>>, secret_box: &CryptoSecretbox) -> Result<Vec<u8>> {
    let successfully_combined_shares: Vec<Vec<u8>> = shares.map(|s| try_to_read_stored_data(s.as_slice())).into_iter()
        .filter_map(Result::ok)
        .collect();

    return combine_data_shares(successfully_combined_shares, secret_box);
}


#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;

    #[test]
    fn split_and_combine_works_with_any_n_and_more_of_m_shards() {
        let shared_secret = "supersecret";
        for m in (1..=5) {
            for n in (1..=m) {
                let (shards, secretbox) = split(shared_secret.as_bytes(), 1.0, m, n).unwrap();
                for i in (1..=n) {
                    for shards_by_n in shards.as_slice().to_vec().into_iter().combinations(i as usize) {
                        let result = combine(shards_by_n, &secretbox);
                        assert_eq!(result.is_ok(), i >= n);
                        if result.is_ok() {
                            let combined_string = String::from_utf8(result.unwrap()).unwrap();
                            assert_eq!(shared_secret, combined_string);
                        }
                    }
                }
            }
        }
    }
}