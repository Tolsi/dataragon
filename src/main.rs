use base58::ToBase58;
use map_in_place::MapVecInPlace;
use structopt::StructOpt;
use crate::shamir::create_data_shares;
use crate::serialization::paranoid_checksum;
use crate::ecc::encode_with_ecc;
use crate::error::*;
use crate::serialization::add_ecc_and_crc;

use objects::*;

mod ecc;
mod shamir;
mod objects;
mod serialization;
mod dataragon;
mod error;

#[derive(StructOpt)]
#[structopt(name = "Dataragon", about = "Dataragon splits the secret to the shares and recovers them")]
enum DataragonCommands {
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
    Recover {
        #[structopt(long)]
        shares: Vec<String>,
        #[structopt(long)]
        all: bool,
        repository: Option<String>
    }
}

fn split(sp: DataragonCommands::Split) {
    let read_result_from_tty = rpassword::read_password_from_tty(Some("Enter your secret (the input is hidden): "));
    let password = read_result_from_tty
        .unwrap_or_else(|_| rpassword::prompt_password_stdout("Enter your secret (the input is hidden): ").unwrap());

    let text = password.as_bytes();
    let allowed_data_damage_level = 1.0;

    dataragon::split(text, allowed_data_damage_level, sp.count, sp.threshold).map(|(shares, secret_box)| {
        let encoded_secret_box: Vec<u8> = bincode::serialize(&secret_box).unwrap();
        let encoded_secret_box_with_ecc_and_crc: Vec<u8> = add_ecc_and_crc(encoded_secret_box, allowed_data_damage_level);

        println!("Shares: {:?}", shares.map(|s| s.to_base58()));
        println!("Encrypted box: {:?}", encoded_secret_box_with_ecc_and_crc.to_base58());
    }).unwrap();
}

fn main() {
    match DataragonCommands::from_args() {
        s@DataragonCommands::Split {c,t} => split(s),
        r@DataragonCommands::Recover {c,t} => {}

    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecc_works_with_only_ecc_corruption() {}
}
