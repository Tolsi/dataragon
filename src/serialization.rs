extern crate sha2;
extern crate crc;

use crc::{crc16};
use sha2::{Sha512, Digest};

pub fn paranoid_checksum(data: &[u8]) -> u16 {
    let mut hasher = Sha512::new();
    hasher.input(data);
    let result = hasher.result();
    return crc16::checksum_usb(result.as_slice());
}