extern crate serde;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct StoredData {
    pub crc_algorithm: u8,
    pub crc: Vec<u8>,
    pub ecc_algorithm: u8,
    pub ecc: Vec<u8>,
    pub encrypted_algorithm: u8,
    pub data:Vec<u8>
}