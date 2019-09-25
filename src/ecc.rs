extern crate reed_solomon;

use reed_solomon::{Encoder, Buffer};
use reed_solomon::Decoder;
use std::error::Error;
use reed_solomon::DecoderError;

pub fn encode_with_ecc(data: &[u8], ecc_len: usize) -> Buffer {
    // Length of error correction code
    let enc = Encoder::new(ecc_len);
    return enc.encode(&data[..]);
}

pub fn recover_with_ecc(data: Buffer, ecc_len: usize) -> Result<Buffer, DecoderError> {
    // Length of error correction code
    let dec = Decoder::new(ecc_len);
    return dec.correct(&*data, None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecc_works_with_sequential_data_and_ecc_corruption() {
        let data = "abc".as_bytes();
        for allowed_data_damage_level_step in 1..=5 {
            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;
            let ecc_len = data.len() * (2 as f32 * allowed_data_damage_level) as usize;


            // Encode data
            let encoded = encode_with_ecc(data, ecc_len);

            // Simulate some transmission errors
            let mut corrupted = encoded.clone();
            let corrupt_bytes = (data.len() as f32 * allowed_data_damage_level) as usize;
            for i in 0..corrupt_bytes {
                corrupted[i] = 0x0;
            }

            // Try to recover data
            let recovered = recover_with_ecc(corrupted, ecc_len).unwrap();

            assert_eq!(data, recovered.data());
        }
    }
}