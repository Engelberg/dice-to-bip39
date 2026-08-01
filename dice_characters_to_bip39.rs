use std::env;
use std::fs;
use std::process;

const BECH32_ALPHABET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// SHA-256 of the 2,048 official English words joined by LF, including final LF.
const BIP39_ENGLISH_WORDLIST_SHA256: &str =
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

fn decode_entropy(text: &str) -> Result<[u8; 16], String> {
    let text = text.trim().to_ascii_lowercase();
    let chars: Vec<char> = text.chars().collect();

    if chars.len() != 26 {
        return Err(format!(
            "Expected exactly 26 characters, received {}.",
            chars.len()
        ));
    }

    let mut entropy: u128 = 0;

    for (position, character) in chars.iter().enumerate() {
        let value = BECH32_ALPHABET
            .find(*character)
            .ok_or_else(|| format!("Invalid character: {character:?}"))?
            as u128;

        if position < 25 {
            // First 25 characters contribute all five bits.
            entropy = (entropy << 5) | value;
        } else {
            // Final character contributes only its three most significant bits.
            entropy = (entropy << 3) | (value >> 2);
        }
    }

    Ok(entropy.to_be_bytes())
}

fn sha256(message: &[u8]) -> [u8; 32] {
    // Initial SHA-256 hash values.
    let mut hash: [u32; 8] = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    // SHA-256 round constants.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_length = (message.len() as u64) * 8;

    let mut padded = message.to_vec();
    padded.push(0x80);

    while padded.len() % 64 != 56 {
        padded.push(0);
    }

    padded.extend_from_slice(&bit_length.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];

        for i in 0..16 {
            let start = i * 4;
            words[i] = u32::from_be_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }

        for i in 16..64 {
            let s0 = words[i - 15].rotate_right(7)
                ^ words[i - 15].rotate_right(18)
                ^ (words[i - 15] >> 3);

            let s1 = words[i - 2].rotate_right(17)
                ^ words[i - 2].rotate_right(19)
                ^ (words[i - 2] >> 10);

            words[i] = words[i - 16]
                .wrapping_add(s0)
                .wrapping_add(words[i - 7])
                .wrapping_add(s1);
        }

        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut f = hash[5];
        let mut g = hash[6];
        let mut h = hash[7];

        for i in 0..64 {
            let sigma1 =
                e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);

            let choose = (e & f) ^ ((!e) & g);

            let temp1 = h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(K[i])
                .wrapping_add(words[i]);

            let sigma0 =
                a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);

            let majority = (a & b) ^ (a & c) ^ (b & c);

            let temp2 = sigma0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }

    let mut output = [0u8; 32];

    for (i, word) in hash.iter().enumerate() {
        output[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }

    output
}

fn load_wordlist(filename: &str) -> Result<Vec<String>, String> {
    let contents = fs::read_to_string(filename)
        .map_err(|error| format!("Could not read {filename:?}: {error}"))?;

    let words: Vec<String> = contents
        .lines()
        .map(str::trim)
        .filter(|word| !word.is_empty())
        .map(String::from)
        .collect();

    if words.len() != 2048 {
        return Err(format!(
            "Expected 2048 BIP39 words, found {}.",
            words.len()
        ));
    }

    // Hash a canonical rendering so LF and CRLF source files behave identically.
    let canonical_wordlist = words.join("\n") + "\n";
    let actual_hash = hex_encode(&sha256(canonical_wordlist.as_bytes()));

    if actual_hash != BIP39_ENGLISH_WORDLIST_SHA256 {
        return Err(format!(
            "The wordlist does not match the official English BIP39 list. \
             Expected SHA-256 {BIP39_ENGLISH_WORDLIST_SHA256}, \
             but found {actual_hash}."
        ));
    }

    Ok(words)
}

fn entropy_to_mnemonic(
    entropy: [u8; 16],
    wordlist: &[String],
) -> Result<String, String> {
    if wordlist.len() != 2048 {
        return Err("The word list must contain 2048 words.".to_string());
    }

    let entropy_number = u128::from_be_bytes(entropy);

    // For 128-bit BIP39 entropy, use the first four bits of SHA-256.
    let checksum = (sha256(&entropy)[0] >> 4) as u16;

    let mut indices = [0usize; 12];

    /*
       The full BIP39 value has 132 bits, which does not fit in u128.
       Rather than using a larger integer, extract the first 11 words
       directly from the entropy, then construct the final word from:

           final 7 entropy bits + 4 checksum bits
    */

    for position in 0..11 {
        let shift = 128 - 11 * (position + 1);
        indices[position] = ((entropy_number >> shift) & 0x7ff) as usize;
    }

    let final_entropy_bits = (entropy_number & 0x7f) as u16;
    indices[11] = ((final_entropy_bits << 4) | checksum) as usize;

    let mnemonic = indices
        .iter()
        .map(|index| wordlist[*index].as_str())
        .collect::<Vec<_>>()
        .join(" ");

    Ok(mnemonic)
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().collect();

    if arguments.len() != 3 {
        return Err(format!(
            "Usage: {} <26-character entropy> <english.txt>",
            arguments
                .first()
                .map(String::as_str)
                .unwrap_or("dice_characters_to_bip39")
        ));
    }

    let characters = &arguments[1];
    let wordlist = load_wordlist(&arguments[2])?;
    let entropy = decode_entropy(characters)?;
    let mnemonic = entropy_to_mnemonic(entropy, &wordlist)?;

    println!("Input characters:   {}", characters.to_ascii_lowercase());
    println!("Entropy hex:     {}", hex_encode(&entropy));
    println!("BIP39 mnemonic:  {mnemonic}");

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        process::exit(1);
    }
}
