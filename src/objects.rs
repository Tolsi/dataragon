extern crate serde;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct StoredData {
    pub version: u8,
    pub crc_algorithm: u8,
    pub crc: Vec<u8>,
    pub ecc_algorithm: u8,
    pub ecc: Vec<u8>,
    pub encrypted_algorithm: u8,
    pub data: Vec<u8>,
}

/// Stores an encrypted message with a message authentication tag
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CryptoSecretbox {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}