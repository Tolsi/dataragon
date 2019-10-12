extern crate serde;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct StoredData {
    pub data: Vec<ECCData>
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
// todo rename
pub struct ECCData {
    #[serde(with = "varint")]
    pub ecc_algorithm: u64,
    pub ecc: Vec<u8>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Header {
    #[serde(with = "varint")]
    pub version: u64,
    #[serde(with = "varint")]
    pub encryption_algorithm: u64,
    #[serde(with = "varint")]
    pub data_len: u64,
    #[serde(with = "varint")]
    pub crc_algorithm: u64,
    pub crc: Vec<u8>,
}

/// Stores an encrypted message with a message authentication tag
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CryptoSecretbox {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}