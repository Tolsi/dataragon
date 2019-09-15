mod ecc;
mod shamir;
mod objects;
mod serialization;

use structopt::StructOpt;


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
    t: u8
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

    // todo check ecc_len < u8.max
    let ecc_len = text.len() * (2 as f32 * allowed_data_damage_level) as usize;
    // Encode data
    let encoded = ecc::encode_with_ecc(text, ecc_len);

    let format_version: u8 = 0;
    let stored = objects::StoredData {
        crc_algorithm: 0,
        crc: Vec::from(&serialization::paranoid_checksum(text).to_be_bytes() as &[u8]),
        ecc_algorithm: 0,
        ecc: Vec::from(encoded.ecc()),
        encrypted_algorithm: 0,
        data: Vec::from(encoded.data())
    };

    let encoded: Vec<u8> = bincode::serialize(&stored).unwrap();
    let decoded: objects::StoredData = bincode::deserialize(&encoded[..]).unwrap();

    println!("{:?}", encoded);
    println!("{:?}", encoded.len());
    ecc::print_ecc(text, 1.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecc_works_with_only_ecc_corruption() {
    }
}