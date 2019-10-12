extern crate crc;
extern crate sha2;

use std::io::Read;

use crc::crc16;
use reed_solomon::Buffer;
use sha2::{Digest, Sha512};

use crate::ecc::{create_ecc, recover_with_ecc};
use crate::error::*;
use crate::objects::*;
use heapless::consts::*;
use as_slice::AsSlice;

const HEADER_LENGTH: usize = 10;

pub fn paranoid_checksum(data: &[u8]) -> u16 {
    let mut hasher = Sha512::new();
    hasher.input(data);
    let result = hasher.result();
    return crc16::checksum_usb(result.as_slice());
}

// todo Hamming Error Correcting Code?
// todo insert crc and data size every N bytes and determine the correct by number of coincidences?
pub fn insert_header_in_data_crc(data: &[u8], header: &[u8]) -> Vec<u8> {
    [header, data].concat()
}

pub fn add_ecc_and_crc(data: Vec<u8>, allowed_data_damage_level: f32) -> Result<Vec<u8>> {
    return if data.len() > 0 {
        let ecc_data = create_ecc(data.as_slice(), allowed_data_damage_level);

        let header = Header {
            version: 0,
            encryption_algorithm: 0,
            data_len: data.len() as u64,
            crc_algorithm: 0,
            crc: Vec::from(&paranoid_checksum(data.as_slice()).to_be_bytes() as &[u8]),
        };

        postcard::to_vec(&header).and_then(|serialized_header: heapless::Vec<u8, U20>| {
            // todo allow cutting data with valid serialization/deserialization
            // todo check different data sizes
            postcard::to_vec(&StoredData { data: ecc_data }).map(|r: heapless::Vec<u8, U2048>|
                insert_header_in_data_crc(r.as_slice(), serialized_header.as_slice())
            )
        }).map_err(|e| ErrorKind::StoredDataSerializationError(e).into())
    } else {
        Err(ErrorKind::EmptyData.into())
    };
}

pub fn try_to_extract_header(data: &[u8]) -> Result<(Header, Vec<u8>)> {
    postcard::from_bytes(data.take(HEADER_LENGTH as u64).get_ref())
        .map_err(|e| Box::from(ErrorKind::StoredDataDeserializationError(e)))
}

pub fn try_to_recover_data_with_ecc(data: &[u8], header: &Header, other_ecc: &[&ECCData]) -> Option<Vec<u8>> {
    let data_len_is_corrupted = header.data_len == 0;
    other_ecc.iter().find_map(|ecc| {
        match ecc.ecc_algorithm {
            0 => {
                ecc.ecc.windows(header.data_len as usize).find_map(|chunk| {
                    if paranoid_checksum(chunk).to_be_bytes() == header.crc.as_slice() {
                        Some(chunk.to_vec())
                    } else {
                        None
                    }
                })
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
    })
}

pub fn try_to_read_stored_data(data: &[u8]) -> Result<Vec<u8>> {
    let header_result: Result<(Header, Vec<u8>)> = try_to_extract_header(data);
    header_result.and_then(|(header, data_bytes)| {
        let try_to_deserialize: Result<StoredData> = postcard::from_bytes(data_bytes.as_slice())
            .map_err(|e| Box::from(ErrorKind::StoredDataDeserializationError(e)));
        try_to_deserialize.and_then(|stored_data| {
            let plain_copies: Vec<&ECCData> = stored_data.data.iter().filter(|d| d.ecc_algorithm == 0).collect();
            let other_ecc: Vec<&ECCData> = stored_data.data.iter().filter(|d| d.ecc_algorithm != 0).collect();
            let valid_copy_option = plain_copies.iter().find(|d| paranoid_checksum(d.ecc.as_slice()).to_be_bytes() == header.crc.as_slice());
            match valid_copy_option {
                // if found not broken
                Some(ecc) => Ok(ecc.ecc.as_slice().to_vec()),
                None => plain_copies.iter().find_map(|data| try_to_recover_data_with_ecc(data.ecc.as_slice(), &header, other_ecc.as_slice()))
                    .ok_or(Box::from(ErrorKind::ECCRecoveryError))
            }
        })
    })
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
            corrupted[3] = 0;
            corrupted[4] = 0;

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
            for i in 20..20 + corrupt_bytes {
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
            let mut corrupted = [&encoded[0..7], &encoded[7 + cut_bytes..encoded.len()]].concat();
            // cut ecc size
            corrupted[16] = (corrupted[16] - cut_bytes as u8) as u8;

            // corrupt even 1 data byte
            corrupted[encoded.len() - cut_bytes - data.len()] = 0;

            // Try to recover data
            let recovered = try_to_read_stored_data(corrupted.as_slice());

            assert_eq!(data, recovered.unwrap().as_slice());
        }
    }
}