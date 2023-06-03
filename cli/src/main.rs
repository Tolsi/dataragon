use std::collections::HashMap;

use itertools::Itertools;
use map_in_place::MapVecInPlace;
use structopt::StructOpt;

use dataragon::objects::*;
use dataragon::serialization;

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
    #[structopt(name = "combine")]
    Combine {
        #[structopt(long = "shares")]
        shares: Vec<String>,
        #[structopt(long = "secretbox")]
        secretbox: String,
    },
}

fn split(count: u8, threshold: u8) {
    let read_password = rpassword::prompt_password("Enter your secret (the input is hidden): ");
    let password = read_password
        .unwrap_or_else(|_| rpassword::prompt_password("Enter your secret (the input is hidden): ").unwrap());

    let text = password.as_bytes();
    let allowed_data_damage_level = 1.0;

    dataragon::split(text, allowed_data_damage_level, count, threshold).and_then(|(shares, secret_box)| {
        let encoded_secret_box: heapless::Vec<u8, 16384> = postcard::to_vec(&secret_box).unwrap();
        return serialization::add_ecc_and_crc(encoded_secret_box.to_vec(), allowed_data_damage_level).map(|encoded_secret_box_with_ecc_and_crc| {
            println!("Shares: {:?}", shares.map(|s| bs58::encode(s).into_string()));
            println!("Encrypted box: {:?}", bs58::encode(encoded_secret_box_with_ecc_and_crc).into_string());
        });
    }).unwrap();
}

fn combine(shares: Vec<String>, secretbox_string: String) {
    let secretbox = bs58::decode(secretbox_string).into_vec();
    let sb = serialization::try_to_read_stored_data(secretbox.unwrap().as_slice()).unwrap();
    let secret_box_bytes = sb.as_slice();
    let secret_box: CryptoSecretbox = postcard::from_bytes(&secret_box_bytes).unwrap();
    dataragon::combine(shares.map(|s| bs58::decode(s).into_vec().unwrap()), &secret_box).map(|r| {
        println!("Result: '{}'", String::from_utf8(r).unwrap());
    }).unwrap();
}

fn main() {
    match DataragonCommands::from_args() {
        DataragonCommands::Split { count, threshold } => split(count, threshold),
        DataragonCommands::Combine { shares, secretbox } => combine(shares, secretbox)
    }
}
