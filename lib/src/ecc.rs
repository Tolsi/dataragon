extern crate reed_solomon;

use reed_solomon::{Buffer, Encoder};
use reed_solomon::Decoder;
use reed_solomon::DecoderError;

use crate::objects::ECCData;

pub fn copy_n_times(data: &[u8], times: usize) -> Vec<ECCData> {
    let mut result = Vec::with_capacity(times as usize);
    for _ in 0..times {
        result.push(ECCData {ecc_algorithm: 0, ecc: Vec::from(data)})
    }
    return result;
}

pub fn create_ecc(data: &[u8], allowed_data_damage_level: f32) -> Vec<ECCData> {
    let mut reed_solomon_damage_level = (data.len() as f32 * allowed_data_damage_level) % 1.0;
    let copy_damage_level = (data.len() as f32 * allowed_data_damage_level) / 1.0;
    let mut copy_ecc_times = copy_damage_level as usize;
    if copy_ecc_times > 1 && reed_solomon_damage_level == 0.0 {
        reed_solomon_damage_level = 1.0;
        copy_ecc_times -= 1;
    };
    let reed_solomon_ecc_len = data.len() * (2.0 * reed_solomon_damage_level) as usize;
    let mut result: Vec<ECCData> = Vec::new();
    if reed_solomon_ecc_len > 0 {
        let ecc_buffer = encode_reed_solomon(data, reed_solomon_ecc_len);
        result.push(ECCData { ecc_algorithm: 1, ecc: Vec::from(ecc_buffer.ecc()) })
    }
    if copy_ecc_times > 0 {
        result.extend(copy_n_times(data, copy_ecc_times));
    }

    result.push(ECCData {ecc_algorithm: 0, ecc: Vec::from(data)});

    return result;
}

// todo warning if data array len will be corrupted, then only 255-ECC_BYTES can be recovered
// todo move recovery from serialization
pub fn recover_with_ecc(data: Buffer, ecc_len: usize) -> Result<Buffer, DecoderError> {
    // Length of error correction code
    let dec = Decoder::new(ecc_len);
    return dec.correct(&*data, None);
}

pub fn encode_reed_solomon(data: &[u8], ecc_len: usize) -> Buffer {
    // Length of error correction code
    let enc = Encoder::new(ecc_len);
    return enc.encode(&data[..]);
}

pub fn recover_reed_solomon(data: Buffer, ecc_len: usize) -> Result<Buffer, DecoderError> {
    // Length of error correction code
    let dec = Decoder::new(ecc_len);
    return dec.correct(&*data, None);
}

#[cfg(test)]
mod tests {
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    use super::*;

    // todo try to remove the data and the start of ecc
    #[test]
    fn ecc_works_with_sequential_data_and_ecc_corruption() {
        let data = "1234567890".as_bytes();
        for allowed_data_damage_level_step in 1..=5 {
            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;
            let ecc_len = data.len() * (2 as f32 * allowed_data_damage_level) as usize;


            // Encode data
            let encoded = encode_reed_solomon(data, ecc_len);

            // Simulate some transmission errors
            let mut corrupted = encoded.clone();
            let corrupt_bytes = (data.len() as f32 * allowed_data_damage_level) as usize;
            for i in 0..corrupt_bytes {
                corrupted[i] = 0x0;
            }

            // Try to recover data
            let recovered = recover_reed_solomon(corrupted, ecc_len).unwrap();

            assert_eq!(data, recovered.data());
        }
    }

    #[test]
    fn ecc_works_with_errors_in_any_sequential_data_parts() {
        let data = "1234567890".as_bytes();

        let allowed_data_damage_level = 0.5;
        let ecc_len = data.len() * (2 as f32 * allowed_data_damage_level) as usize;

        // Encode data
        let encoded = encode_reed_solomon(data, ecc_len);

        let corrupt_bytes = (data.len() as f32 * allowed_data_damage_level) as usize;

        let sl: Vec<_> = (0..data.len()).collect();
        for idx in sl.windows(corrupt_bytes) {
            // Simulate some transmission errors
            let mut corrupted = encoded.clone();
            for i in *idx.first().unwrap()..*idx.last().unwrap() {
                corrupted[i] = 0x0;
            }

            // Try to recover data
            let recovered = recover_reed_solomon(corrupted, ecc_len).unwrap();

            assert_eq!(data, recovered.data());
        }
    }

    #[test]
    fn ecc_works_with_errors_in_random_data_parts() {
        let data = "1234567890".as_bytes();

        let allowed_data_damage_level = 0.5;
        let ecc_len = data.len() * (2 as f32 * allowed_data_damage_level) as usize;

        // Encode data
        let encoded = encode_reed_solomon(data, ecc_len);

        let corrupt_bytes = (data.len() as f32 * allowed_data_damage_level) as usize;

        for _ in 0..100 {
            let mut rng = thread_rng();
            let sl: Vec<_> = (0..data.len()).collect();

            // Simulate some transmission errors
            let mut corrupted = encoded.clone();
            for i in sl.choose_multiple(&mut rng, corrupt_bytes) {
                corrupted[*i] = 0x0;
            }
            // Try to recover data
            let recovered = recover_reed_solomon(corrupted, ecc_len).unwrap();

            assert_eq!(data, recovered.data());
        }
    }
}