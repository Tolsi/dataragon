use base58::ToBase58;
use map_in_place::MapVecInPlace;
use structopt::StructOpt;
use crate::shamir::create_data_shares;
use crate::serialization::paranoid_checksum;
use crate::ecc::encode_with_ecc;
use crate::serialization::add_ecc_and_crc;

use objects::*;

mod ecc;
mod shamir;
mod objects;
mod serialization;
mod dataragon;
mod error;

/// Secret sharing params.
#[derive(StructOpt)]
struct SharingParams {
    /// The pattern to look for
    #[structopt(short = "c", long = "count")]
    /// Minimal number of parts to recover the secret.
    ///
    /// Blah blah blah shamir's secret sharing scheme blah blah
    c: u8,
    #[structopt(short = "t", long = "threshold")]
    t: u8,
}

fn main() {
    let args = SharingParams::from_args();

    let count = args.c;
    let threshold = args.t;

    let read_result = rpassword::read_password_from_tty(Some("Enter your secret (the input is hidden): "));

    let password = if read_result.is_err() {
        rpassword::prompt_password_stdout("Enter your secret (the input is hidden): ").unwrap()
    } else {
        read_result.unwrap()
    };

    let text = password.as_bytes();
    let allowed_data_damage_level = 1.0;

    let (shares, secret_box) = dataragon::split(text, allowed_data_damage_level, count, threshold);

    let encoded_secret_box: Vec<u8> = bincode::serialize(&secret_box).unwrap();
    let encoded_secret_box_with_ecc_and_crc: Vec<u8> = add_ecc_and_crc(encoded_secret_box, allowed_data_damage_level);

    println!("Shares: {:?}", shares.map(|s| s.to_base58()));
    println!("Encrypted box: {:?}", encoded_secret_box_with_ecc_and_crc.to_base58());
    ecc::debug_ecc(text, allowed_data_damage_level);


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecc_works_with_only_ecc_corruption() {}
}
