use map_in_place::MapVecInPlace;
use structopt::StructOpt;
use crate::shamir::create_data_shares;
use crate::serialization::paranoid_checksum;
use crate::ecc::encode_with_ecc;
use crate::error::*;
use crate::serialization::add_ecc_and_crc;

use objects::*;
use secrets::SecretBox;

mod ecc;
mod shamir;
mod objects;
mod serialization;
mod dataragon;
mod error;

#[derive(Debug, StructOpt)]
#[structopt(name = "Dataragon", about = "Dataragon splits the secret to the shares and recovers them")]
enum DataragonCommands {
    #[structopt(name = "split")]
    Split {
        #[structopt(short = "c", long = "count")]
        /// Minimal number of parts to recover the secret.
        ///
        /// Blah blah blah shamir's secret sharing scheme blah blah
        count: u8,
        #[structopt(short = "t", long = "threshold")]
        // Threshold
        threshold: u8,
    },
    #[structopt(name = "restore")]
    Restore {
        #[structopt(long = "shares")]
        shares: Vec<String>,
        #[structopt(long = "secretbox")]
        secretbox: String
    }
}

fn split(count: u8, threshold: u8) {
    let read_result_from_tty = rpassword::read_password_from_tty(Some("Enter your secret (the input is hidden): "));
    let password = read_result_from_tty
        .unwrap_or_else(|_| rpassword::prompt_password_stdout("Enter your secret (the input is hidden): ").unwrap());

    let text = password.as_bytes();
    let allowed_data_damage_level = 1.0;

    dataragon::split(text, allowed_data_damage_level, count, threshold).map(|(shares, secret_box)| {
        let encoded_secret_box: Vec<u8> = bincode::serialize(&secret_box).unwrap();
        let encoded_secret_box_with_ecc_and_crc: Vec<u8> = add_ecc_and_crc(encoded_secret_box, allowed_data_damage_level);

        println!("Shares: {:?}", shares.map(|s| bs58::encode(s).into_string()));
        println!("Encrypted box: {:?}", bs58::encode(encoded_secret_box_with_ecc_and_crc).into_string());
    }).unwrap();
}

fn restore(shares: Vec<String>, secretbox_string: String) {
    let secretbox = bs58::decode(secretbox_string).into_vec();
    let sb = serialization::try_to_read_bytes_with_crc_and_ecc(secretbox.unwrap().as_slice()).unwrap();
    let secret_box_bytes = sb.as_slice();
    let secret_box: CryptoSecretbox = bincode::deserialize(&secret_box_bytes).unwrap();
    dataragon::restore(shares.map(|s| bs58::decode(s).into_vec().unwrap()), &secret_box).map(|r| {
        println!("Result: '{}'", String::from_utf8(r).unwrap());
    }).unwrap();
}

fn main() {
    match DataragonCommands::from_args() {
        DataragonCommands::Split { count, threshold } => split(count, threshold),
        DataragonCommands::Restore { shares, secretbox } => restore(shares, secretbox)
    }
}
