extern crate crc;
extern crate sha2;

use crc::crc16;
use itertools::free::all;
use reed_solomon::Buffer;
use sha2::{Digest, Sha512};

use crate::ecc::{create_ecc, encode_reed_solomon, recover_with_ecc};
use crate::error::*;
use crate::objects::{CRCData, EncryptedData, StoredData};

pub fn paranoid_checksum(data: &[u8]) -> u16 {
    let mut hasher = Sha512::new();
    hasher.input(data);
    let result = hasher.result();
    return crc16::checksum_usb(result.as_slice());
}

pub fn add_ecc_and_crc(data: Vec<u8>, allowed_data_damage_level: f32) -> Result<Vec<u8>> {
    return if data.len() > 0 {
        let ecc_data = create_ecc(data.as_slice(), allowed_data_damage_level);

        // todo insert crc and data size every N bytes and determine the correct by number of coincidences?
        let stored = StoredData {
            version: 0,
            crc_data: CRCData {
                crc_algorithm: 0,
                crc: Vec::from(&paranoid_checksum(data.as_slice()).to_be_bytes() as &[u8]),
            },
            ecc_data: ecc_data,
            encrypted_data: EncryptedData {
                encryption_algorithm: 0,
                data,
            },
        };

        // todo allow cutting data with valid serialization/deserialization
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
        if paranoid_checksum(stored_data.encrypted_data.data.as_slice()).to_be_bytes() == stored_data.crc_data.crc.as_slice() {
            // if decrypted
            Ok(stored_data.encrypted_data.data)
        } else if (stored_data.ecc_data.len() > 0) {
            let data_len_is_corrupted = stored_data.encrypted_data.data.len() == 0;

            let data = stored_data.encrypted_data.data.as_slice();
            stored_data.ecc_data.iter().find_map(|ecc| {
                match ecc.ecc_algorithm {
                    0 => {
                        if (!data_len_is_corrupted) {
                            // todo try to combine bytes from corrupted data and ecc
                            ecc.ecc.windows(data.len()).find_map(|chunk| {
                                if paranoid_checksum(chunk).to_be_bytes() == stored_data.crc_data.crc.as_slice() {
                                    Some(chunk.to_vec())
                                } else {
                                    None
                                }
                            })
                        } else {
                            // todo add force restore parameter?
                            (1..256).find_map(|i| ecc.ecc.windows(i).find_map(|chunk|
                                if paranoid_checksum(chunk).to_be_bytes() == stored_data.crc_data.crc.as_slice() {
                                    Some(chunk.to_vec())
                                } else {
                                    None
                                }))
                        }
                    }
                    1 => {
                        let data = if data_len_is_corrupted {
                            // todo warning if data array len will be corrupted, then only 255-ECC_BYTES can be recovered
                            // Polynom::POLYNOMIAL_MAX_LENGTH - ECC
                            vec![0; 255 - ecc.ecc.len()]
                        } else {
                            data.to_vec()
                        };
                        let data_and_ecc_bytes = [data.as_slice(), ecc.ecc.as_slice()].concat();
                        recover_with_ecc(Buffer::from_slice(data_and_ecc_bytes.as_slice(), data_and_ecc_bytes.len()), ecc.ecc.len())
                            .map(|r| {
                                let mut data_vec = r.data().to_vec();
                                if data_len_is_corrupted {
                                    let leading_zeros = data_vec.iter().take_while(|b| **b == 0).count();
                                    data_vec.drain(leading_zeros..data_vec.len()).collect()
                                } else {
                                    data_vec
                                }
                            }).ok()
                    }
                    _ => None
                }
            }).ok_or(Box::from(ErrorKind::ECCRecoveryError))
        } else {
            Err(Box::from(ErrorKind::ECCRecoveryError))
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_works_with_corrupted_data_from_the_end() {
        let data = "1234567890".as_bytes();
        // only works until 18 because of ECC size (and POLYNOMIAL_MAX_LENGTH in the end)
        for allowed_data_damage_level_step in 1..18 {
            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;

            // Encode data
            let encoded = add_ecc_and_crc(data.to_vec(), allowed_data_damage_level).unwrap();

            // Simulate some transmission errors
            let mut corrupted = encoded.clone();

            let corrupt_bytes = (data.len() as f32 * allowed_data_damage_level - 1.0) as usize;
            for i in encoded.len() - corrupt_bytes..encoded.len() {
                corrupted[i] = 0;
            }

            // Try to recover data
            let recovered = try_to_read_stored_data(corrupted.as_slice());

            assert_eq!(data, recovered.unwrap().as_slice());
        }
    }

    // todo try to find crc and data size in many places
    #[test]
    fn combine_works_with_some_corrupted_crcs() {
        let data = "1234567890".as_bytes();
        // only works until 18 because of ECC size (and POLYNOMIAL_MAX_LENGTH in the end)
        for allowed_data_damage_level_step in 1..=17 {
            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;

            // Encode data
            let encoded = add_ecc_and_crc(data.to_vec(), allowed_data_damage_level).unwrap();

            // Simulate some transmission errors
            let mut corrupted = encoded.clone();
            // corrupt crc
            corrupted[10] = 0;
            corrupted[11] = 0;
            let corrupt_bytes = (data.len() as f32 * allowed_data_damage_level - 1.0) as usize;

            // corrupt even 1 data byte
            corrupted[encoded.len() - data.len()] = 0;

            // Try to recover data
            let recovered = try_to_read_stored_data(corrupted.as_slice());

            assert_eq!(data, recovered.unwrap().as_slice());
        }
    }

    // todo what I want to test here?! :D
    #[test]
    fn combine_works_with_corrupted_data_from_the_ecc_start() {
        let data = "1234567890".as_bytes();
        // only works until 18 because of ECC size (and POLYNOMIAL_MAX_LENGTH in the end)
        for allowed_data_damage_level_step in 1..=17 {
            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;

            // Encode data
            let encoded = add_ecc_and_crc(data.to_vec(), allowed_data_damage_level).unwrap();

            // Simulate some transmission errors
            let mut corrupted = encoded.clone();

            let corrupt_bytes = (data.len() as f32 * allowed_data_damage_level - 1.0) as usize;
            for i in 29..29 + corrupt_bytes {
                corrupted[i] = 0;
            }

            // corrupt even 1 data byte
            corrupted[encoded.len() - data.len()] = 0;

            // Try to recover data
            let recovered = try_to_read_stored_data(corrupted.as_slice());

            assert_eq!(data, recovered.unwrap().as_slice());
        }
    }

    #[test]
    fn ecc_recovery_should_works_with_partial_ecc_cut_from_start() {
        let data = "1234567890".as_bytes();
        for allowed_data_damage_level_step in 1..=5 {
            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;

            // Encode data
            let encoded = add_ecc_and_crc(data.to_vec(), allowed_data_damage_level).unwrap();

            // Simulate some transmission errors
            let cut_bytes = (data.len() as f32 * allowed_data_damage_level - 1.0) as usize;
            let mut corrupted = [&encoded[0..29], &encoded[29 + cut_bytes..encoded.len()]].concat();
            // cut ecc size
            corrupted[21] = (corrupted[21] - cut_bytes as u8) as u8;

            // corrupt even 1 data byte
            corrupted[encoded.len() - cut_bytes - data.len()] = 0;

            // Try to recover data
            let recovered = try_to_read_stored_data(corrupted.as_slice());

            assert_eq!(data, recovered.unwrap().as_slice());
        }
    }
}