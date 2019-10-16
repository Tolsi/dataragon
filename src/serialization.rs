extern crate crc;
extern crate sha2;

use std::cmp::max;
use std::collections::HashMap;
use std::hash::Hash;
use std::io::Read;

use as_slice::AsSlice;
use crc::crc16;
use heapless::consts::*;
use integer_encoding::*;
use itertools::*;
use map_in_place::MapVecInPlace;
use reed_solomon::Buffer;
use sha2::{Digest, Sha512};

use crate::ecc::{create_ecc, recover_reed_solomon, recover_with_ecc};
use crate::error::*;
use crate::objects::*;

const HEADER_LENGTH: usize = 6;

pub fn paranoid_checksum(data: &[u8]) -> u16 {
    let mut hasher = Sha512::new();
    hasher.input(data);
    let result = hasher.result();
    return crc16::checksum_usb(result.as_slice());
}

// todo RaptorQ!
// todo labrador_ldpc?
// todo Hamming Error Correcting Code?
// todo insert crc and data size every N bytes and determine the correct by number of coincidences?
pub fn insert_header_in_data_crc(data: &[u8], header: &[u8], allowed_damage_bits: usize) -> Vec<u8> {
    // if in every header copy will be even 1 corrupted bit
    let headers_copies = allowed_damage_bits + 2;
    let total_bytes = (header.len() + 2) * headers_copies + data.len();
    let mut r: Vec<u8> = Vec::with_capacity(total_bytes);
    let data_by_chunk = (data.len() as f32 / headers_copies as f32).ceil() as usize;
    let chunk_size = max(data_by_chunk, 1);
    let header_size = header.len().encode_var_vec();
    for chunk in data.chunks(chunk_size) {
        r.extend(header_size.as_slice());
        r.extend(header);
        r.extend(chunk.len().encode_var_vec().as_slice());
        r.extend(chunk);
    }
    let headers_left = headers_copies as i32 - data.chunks(chunk_size).len() as i32;
    for _ in 0..headers_left {
        r.extend(header_size.as_slice());
        r.extend(header);
    }
    r
}

pub fn frequencies<'a, T, I>(it: I) -> HashMap<&'a T, u32>
    where
        I: IntoIterator<Item=&'a T>,
        T: Eq + Hash
{
    let mut frequency: HashMap<&T, u32> = HashMap::new();
    for item in it {
        *frequency.entry(item).or_insert(0) += 1;
    }
    frequency
}

pub fn filter_valid_header(h: &Header) -> bool {
    h.version == 0 && h.encryption_algorithm == 0 && h.data_len > 0 && h.crc_algorithm == 0
}

pub fn try_to_extract_header(data: &[u8]) -> Result<(Header, Vec<u8>)> {
    let mut sized_chunks: Vec<(u64, &[u8])> = Vec::new();

    let mut from = 0;
    while from < data.len() {
        let (var, space) = u64::decode_var(&data[from..]);
        let until = from + space + var as usize;
        if data.len() < from + space || data.len() < until {
            break;
        }
        sized_chunks.push((var, &data[from + space..until]));
        from = until;
    }

    let gm = sized_chunks.into_iter().into_group_map();

    // todo what if that freq header is wrong?
    let found_headers: Vec<Header> = gm
        .iter().filter(|(k, v)| **k == HEADER_LENGTH as u64)
        .flat_map(|(k, v)| {
            let parsed_headers: Vec<Header> = v.iter().filter_map(|bytes| postcard::from_bytes::<Header>(bytes).ok()).collect();
            // todo calc freq after all lenghts results map
//            let headers_frequency = frequencies(parsed_headers.iter());
//            let headers_frequency_vec: Vec<(&&Header, &u32)> = headers_frequency.iter().collect();
//            let headers_sorted_by_freq = headers_frequency_vec.iter()
//                .sorted_by_key(|(k, v)| **v)
//                .map(|(k, v)| ***k)
//                .collect::<Vec<Header>>();
//            let parsed_header: Option<&Header> = headers_sorted_by_freq.first();
//            (k, parsed_header.filter(|h| filter_valid_header(h)).map(|r| r.clone()))
            parsed_headers
        }).collect();

    // todo make warning if there're many valid headers?!
//    assert_eq!(found_headers.len(), 1);
    let headers_frequency = frequencies(found_headers.iter());
    let headers_frequency_vec: Vec<(&&Header, &u32)> = headers_frequency.iter().collect();
    let headers_sorted_by_freq = headers_frequency_vec.iter()
        .sorted_by_key(|(k, v)| -(**v as i32))
        .map(|(k, v)| ***k)
        .collect::<Vec<Header>>();
    let parsed_header: Option<&Header> = headers_sorted_by_freq.first();

    let found_data: Vec<&&[u8]> = gm.iter().filter(|(k, v)| **k != HEADER_LENGTH as u64).flat_map(|(k, v)| v).collect();
    let vv = found_data.map(|v| *v);

    parsed_header
        .map(|header| (*header, vv.concat()))
        .ok_or(Box::from(ErrorKind::StoredDataDeserializationError(None)))
}

pub fn add_ecc_and_crc(data: Vec<u8>, allowed_data_damage_level: f32) -> Result<Vec<u8>> {
    return if data.len() > 0 {
        let ecc_data = create_ecc(data.as_slice(), allowed_data_damage_level);
        let crc = paranoid_checksum(data.as_slice()).to_be_bytes();

        let header = Header {
            version: 0,
            encryption_algorithm: 0,
            data_len: data.len() as u64,
            crc_algorithm: 0,
            crc0: crc[0],
            crc1: crc[1],
        };

        postcard::to_vec(&header).and_then(|serialized_header: heapless::Vec<u8, U32>| {
            // todo allow cutting data with valid serialization/deserialization
            // todo check different data sizes
            postcard::to_vec(&StoredData { data: ecc_data }).map(|r: heapless::Vec<u8, U16384>| {
                let allowed_data_damage_bits = (allowed_data_damage_level * data.len() as f32) as usize * 8;
                insert_header_in_data_crc(r.as_slice(), serialized_header.as_slice(), allowed_data_damage_bits)
            })
        }).map_err(|e| ErrorKind::StoredDataSerializationError(e).into())
    } else {
        Err(ErrorKind::EmptyData.into())
    };
}

pub fn try_to_recover_data_with_ecc(data: &[u8], header: &Header, other_ecc: &[&ECCData]) -> Option<Vec<u8>> {
    let data_len_is_corrupted = header.data_len == 0;
    other_ecc.iter().find_map(|ecc| {
        match ecc.ecc_algorithm {
            0 => {
                ecc.ecc.windows(header.data_len as usize).find_map(|chunk| {
                    if paranoid_checksum(chunk).to_be_bytes() == [header.crc0, header.crc1] {
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
                recover_reed_solomon(Buffer::from_slice(data_and_ecc_bytes.as_slice(), data_and_ecc_bytes.len()), ecc.ecc.len())
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
            .map_err(|e| Box::from(ErrorKind::StoredDataDeserializationError(Some(e))));
        try_to_deserialize.and_then(|stored_data| {
            let plain_copies: Vec<&ECCData> = stored_data.data.iter().filter(|d| d.ecc_algorithm == 0).collect();
            let other_ecc: Vec<&ECCData> = stored_data.data.iter().filter(|d| d.ecc_algorithm != 0).collect();
            let valid_copy_option = plain_copies.iter().find(|d| paranoid_checksum(d.ecc.as_slice()).to_be_bytes() == [header.crc0, header.crc1]);
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
                corrupted[i] = 1;
            }

            // Try to recover data
            let recovered = try_to_read_stored_data(corrupted.as_slice());
            let result = recovered.unwrap();

            assert_eq!(data, result.as_slice());
        }
    }

    // todo try to find crc and data size in many places
//    #[test]
//    fn combine_works_with_some_corrupted_crcs() {
//        let data = "1234567890".as_bytes();
//        // only works until 18 because of ECC size (and POLYNOMIAL_MAX_LENGTH in the end)
//        for allowed_data_damage_level_step in 1..=17 {
//            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;
//
//            // Encode data
//            let encoded = add_ecc_and_crc(data.to_vec(), allowed_data_damage_level).unwrap();
//
//            // Simulate some transmission errors
//            let mut corrupted = encoded.clone();
//            // corrupt crc
//            corrupted[3] = 0;
//            corrupted[4] = 0;
//
//            // corrupt even 1 data byte
//            corrupted[encoded.len() - data.len()] = 0;
//
//            // Try to recover data
//            let recovered = try_to_read_stored_data(corrupted.as_slice());
//
//            assert_eq!(data, recovered.unwrap().as_slice());
//        }
//    }

    // todo what I want to test here?! :D
//    #[test]
//    fn combine_works_with_corrupted_data_from_the_ecc_start() {
//        let data = "1234567890".as_bytes();
//        // only works until 18 because of ECC size (and POLYNOMIAL_MAX_LENGTH in the end)
//        for allowed_data_damage_level_step in 1..=17 {
//            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;
//
//            // Encode data
//            let encoded = add_ecc_and_crc(data.to_vec(), allowed_data_damage_level).unwrap();
//
//            // Simulate some transmission errors
//            let mut corrupted = encoded.clone();
//
//            let corrupt_bytes = (data.len() as f32 * allowed_data_damage_level - 1.0) as usize;
//            for i in 20..20 + corrupt_bytes {
//                corrupted[i] = 0;
//            }
//
//            // corrupt even 1 data byte
//            corrupted[encoded.len() - data.len()] = 0;
//
//            // Try to recover data
//            let recovered = try_to_read_stored_data(corrupted.as_slice());
//
//            assert_eq!(data, recovered.unwrap().as_slice());
//        }
//    }

//    #[test]
//    fn ecc_recovery_should_works_with_partial_ecc_cut_from_start() {
//        let data = "1234567890".as_bytes();
//        for allowed_data_damage_level_step in 1..=5 {
//            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;
//
//            // Encode data
//            let encoded = add_ecc_and_crc(data.to_vec(), allowed_data_damage_level).unwrap();
//
//            // Simulate some transmission errors
//            let cut_bytes = (data.len() as f32 * allowed_data_damage_level - 1.0) as usize;
//            let mut corrupted = [&encoded[0..7], &encoded[7 + cut_bytes..encoded.len()]].concat();
//            // cut ecc size
//            corrupted[16] = (corrupted[16] - cut_bytes as u8) as u8;
//
//            // corrupt even 1 data byte
//            corrupted[encoded.len() - cut_bytes - data.len()] = 0;
//
//            // Try to recover data
//            let recovered = try_to_read_stored_data(corrupted.as_slice());
//
//            assert_eq!(data, recovered.unwrap().as_slice());
//        }
//    }
}
