extern crate crc;
extern crate sha2;

use crc::crc16;
use reed_solomon::Buffer;
use sha2::{Digest, Sha512};

use crate::ecc::{encode_with_ecc, recover_with_ecc};
use crate::error::*;
use crate::objects::{CryptoSecretbox, StoredData};

pub fn paranoid_checksum(data: &[u8]) -> u16 {
    let mut hasher = Sha512::new();
    hasher.input(data);
    let result = hasher.result();
    return crc16::checksum_usb(result.as_slice());
}

pub fn add_ecc_and_crc(data: Vec<u8>, allowed_data_damage_level: f32) -> Result<Vec<u8>> {
    return if data.len() > 0 {
        let ecc_len = data.len() * (2 as f32 * allowed_data_damage_level) as usize;
        let encoded = encode_with_ecc(data.as_slice(), ecc_len);

        let format_version: u8 = 0;

        // todo warning if data array len will be corrupted, then only 255-ECC_BYTES can be recovered
        // todo insert crc every N bytes and determine the correct by number of coincidences?
        let stored = StoredData {
            version: 0,
            crc_algorithm: 0,
            crc: Vec::from(&paranoid_checksum(data.as_slice()).to_be_bytes() as &[u8]),
            ecc_algorithm: 0,
            ecc: Vec::from(encoded.ecc()),
            encrypted_algorithm: 0,
            data: Vec::from(data),
        };

        bincode::serialize(&stored)
            .map_err(|e| ErrorKind::StoredDataSerializationError(e).into())
    } else {
        Err(ErrorKind::EmptyData.into())
    };
}


pub fn try_to_read_stored_data(data: &[u8]) -> Result<Vec<u8>> {
    let try_to_deserialize: Result<StoredData> = bincode::deserialize(&data)
        .map_err(|e| Box::from(ErrorKind::StoredDataDeserializationError(e)));
    return try_to_deserialize.and_then(|stored_data|
        if paranoid_checksum(stored_data.data.as_slice()).to_be_bytes() == stored_data.crc.as_slice() {
            Ok(stored_data.data)
        } else {
            let data_len_is_corrupted = stored_data.data.len() == 0;
            let data = if data_len_is_corrupted {
                // Polynom::POLYNOMIAL_MAX_LENGTH - ECC
                vec![0; 255 - stored_data.ecc.len()]
            } else {
                stored_data.data
            };
            let data_and_ecc_bytes = [data.as_slice(), stored_data.ecc.as_slice()].concat();
            recover_with_ecc(Buffer::from_slice(data_and_ecc_bytes.as_slice(), data.len()), stored_data.ecc.len())
                .map(|r| {
                    let mut data_vec = r.data().to_vec();
                    if data_len_is_corrupted {
                        let leading_zeros = data_vec.iter().take_while(|b| **b == 0).count();
                        data_vec.drain(leading_zeros..data_vec.len()).collect()
                    } else {
                        data_vec
                    }
                })
                .map_err(|de| Box::from(ErrorKind::ECCRecoveryError(de)))
        });
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;

    #[test]
    fn combine_works_with_corrupted_data() {
        let data = "1234567890".as_bytes();
        // only works until 18 because of ECC size (and POLYNOMIAL_MAX_LENGTH in the end)
        for allowed_data_damage_level_step in 1..=17 {
            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;

            // Encode data
            let encoded = add_ecc_and_crc(data.to_vec(), allowed_data_damage_level).unwrap();

            // Simulate some transmission errors
            let mut corrupted = encoded.clone();
            let corrupt_bytes = (data.len() as f32 * allowed_data_damage_level) as usize;
            for i in encoded.len() - corrupt_bytes..encoded.len() {
                corrupted[i] = 0x0;
            }

            // Try to recover data
            let recovered = try_to_read_stored_data(corrupted.as_slice());

            assert_eq!(data, recovered.unwrap().as_slice());
        }
    }
}