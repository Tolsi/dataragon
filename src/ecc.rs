extern crate reed_solomon;

use reed_solomon::{Encoder, Buffer};
use reed_solomon::Decoder;

pub fn encode_with_ecc(data: &[u8], ecc_len: usize) -> Buffer {
    // Length of error correction code
    let enc = Encoder::new(ecc_len);
    return enc.encode(&data[..]);
}

pub fn recover_with_ecc(data: Buffer, ecc_len: usize) -> Buffer {
    // Length of error correction code
    let dec = Decoder::new(ecc_len);
    let known_erasures = None;
    let recovered = dec.correct(&*data, known_erasures).unwrap();
    return recovered;
}


pub fn print_ecc(data: &[u8], allowed_data_damage_level: f32) {
    let ecc_len = data.len() * (2 as f32 * allowed_data_damage_level) as usize;

    // Encode data
    let encoded = encode_with_ecc(data, ecc_len);

    let orig_str = std::str::from_utf8(data).unwrap();
    println!("message:               {:?}", orig_str);
    println!("original data:         {:?}", data);
    println!("error correction code: {:?}", encoded.ecc());

    // Simulate some transmission errors
    let mut corrupted = encoded;
    for i in data.len()+6..corrupted.len() {
        corrupted[i] = 0x0;
    }

    println!("corrupted:             {:?}", *corrupted);

    // Try to recover data
    let recovered = recover_with_ecc(corrupted, ecc_len);

    let recv_str = std::str::from_utf8(recovered.data()).unwrap();

    println!("repaired:              {:?}", recv_str);
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
            let recovered = recover_with_ecc(corrupted, ecc_len);

            assert_eq!(data, recovered.data());
        }
    }

    #[test]
    fn ecc_works_with_only_ecc_corruption() {
        let data = "abc".as_bytes();
        for allowed_data_damage_level_step in 1..=5 {
            let allowed_data_damage_level = allowed_data_damage_level_step as f32 * 0.5;
            let ecc_len = data.len() * (2 as f32 * allowed_data_damage_level) as usize;

            // Encode data
            let encoded = encode_with_ecc(data, ecc_len);

            // Simulate some transmission errors
            let mut corrupted = encoded.clone();
            let corrupt_bytes = (ecc_len as f32 * allowed_data_damage_level) as usize;
            for i in data.len()..data.len()+corrupt_bytes {
                corrupted[i] = 0x0;
            }

            // Try to recover data
            let recovered = recover_with_ecc(corrupted, ecc_len);

            assert_eq!(data, recovered.data());
        }
    }
}