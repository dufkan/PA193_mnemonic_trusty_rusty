use sha2::{Sha256, Sha512, Digest};

#[cfg(test)]
mod util;

pub const WORD_LIST: [&str; 2048] = include!("wordlist.in");

/// Get position of word in wordlist
pub fn mnemonic_lookup(mnemonic: &str) -> Result<u16, String> {
    match WORD_LIST.iter().position(|x| x == &mnemonic) {
        None    => Err(format!("Invalid word: {}", mnemonic)),
        Some(v) => Ok(v as u16)
    }
}

/// Compute sha256 of input
fn sha256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(input);
    hasher.result().into_iter().collect()
}

/// Get checksum by entropy in bytes
fn checksum(entropy: &[u8]) -> Result<u8, String> {
    let ent = entropy.len(); // number of bytes
    if ent % 4 != 0 {
        return Err(String::from("Entropy is not multiple of 4!"));
    }

    let cs = ent / 4;
    let header = sha256(entropy)[0]; // first byte of hash
    match cs {
        4 => Ok(header & 0b1111_0000),
        5 => Ok(header & 0b1111_1000),
        6 => Ok(header & 0b1111_1100),
        7 => Ok(header & 0b1111_1110),
        8 => Ok(header),
        _ => Err(String::from("Size of the block is not compatible!")),
    }
}

// Get n-th word of entropy ...
fn get_word(position: usize, entropy: &[u8]) -> &str {
    let mut index: u16 = 0b0000_0000_0000_0000; // n-th mnemonic word of sentence
    let first_bit: usize = position * 11; // first bit of mnemonic word

    // compute each bit of mnemonic word
    for offset in 0..11 {
        let byte = (first_bit + offset) / 8;
        let bit = (first_bit + offset) % 8;
        let bit_value = (entropy[byte] & (128u8 >> bit) as u8) != 0u8;
        if bit_value {
            index |= (1024 >> offset) as u16;
        }
    }

    WORD_LIST[index as usize]
}

/// Get words from entropy
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, String> {
    let mut entropy: Vec<_> = entropy.to_vec();
    let ms = entropy.len() * 3 / 4; // length of mnemonic sentence is 0.75 multiply of initial entropy
    let checksum = checksum(&entropy);
    entropy.push(checksum?); // append checksum to the end of entropy
    let mut result = String::new();
    for index in 0..ms {
        result.push_str(get_word(index, &entropy));
        if index != ms - 1 {
            result.push(' ');
        }
    }
    Ok(result)
}

/// Get entropy from mnemonic
pub fn mnemonic_to_entropy(sentence: &str) -> Result<Vec<u8>, String> {
    let words: Vec<_> = sentence.split(' ').collect();
    const POSSIBLE_LEN: [usize; 5] = [12, 15, 18, 21, 24];
    if !POSSIBLE_LEN.contains(&words.len()) {
        return Err(String::from("Mnemonic sentence could contain just 12, 15, 18, 21 or 24 words!"));
    }

    let mut result = [0u8; 33];
    let mut pos = 0usize; // position of actual bit in entropy
    for word in words {
        let index = mnemonic_lookup(word)?;
        for offset in 0..11 {
            let bit_value = (index & (1024 >> offset as u16)) != 0u16;
            if bit_value {
                result[pos / 8] |= 128u8 >> (pos % 8) as u8;
            }
            pos += 1;
        }
    }
    let checksum_len = pos / 33;
    let entropy = (&result[0..(pos - checksum_len)/8]).to_vec();
    let checksum = checksum(&entropy)?;

    // check if checksum is equal to last byte
    if checksum != result[(pos - checksum_len) / 8] {
        return Err(String::from("Invalid mnemonic checksum!"));
    }
    Ok(entropy)
}

/// Transform a mnemonic to a seed
///
/// # Arguments
///
///  * `mnemonic` - the mnemonic
///  * `passphrase` - an optional passphrase
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: Option<&str>) -> Vec<u8> {
    let mnemonic: Vec<_> = mnemonic.bytes().collect();

    let passphrase = passphrase.unwrap_or("");
    let passphrase = format!("mnemonic{}", passphrase);
    let passphrase: Vec<_> = passphrase.as_str().bytes().collect();

    pbkdf2(&mnemonic, &passphrase, 2048)
}

/// Simplified PBKDF2 using HMAC-SHA512
///
/// Supports only output size equal to the underlying hash size i.e. 64 bytes
fn pbkdf2(password: &[u8], salt: &[u8], iter_count: usize) -> Vec<u8> {
    const INDEX: u32 = 1;

    let mut tmp = Vec::new();
    tmp.extend_from_slice(salt);
    tmp.extend_from_slice(&INDEX.to_be_bytes()[..]);
    tmp = hmac_sha512(&tmp, password);
    let mut result = tmp.clone();

    for _ in 1..iter_count {
        tmp = hmac_sha512(&tmp, password);
        result = xor_bytes(&result, &tmp);
    }

    result
}

/// HMAC-SHA512
fn hmac_sha512(data: &[u8], key: &[u8]) -> Vec<u8> {
    const OPAD: [u8; 128] = [0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c];
    const IPAD: [u8; 128] = [0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36];

    let key = {
        let mut tmp = [0u8; 128];
        if key.len() <= 128 {
            for (idx, &byte) in key.iter().enumerate() {
                tmp[idx] = byte;
            }
        } else {
            let mut hasher = Sha512::new();
            hasher.input(key);
            for (idx, &byte) in hasher.result().iter().enumerate() {
                tmp[idx] = byte;
            }
        }
        tmp
    };

    let key_opad = xor_bytes(&key, &OPAD);
    let key_ipad = xor_bytes(&key, &IPAD);

    let mut hasher = Sha512::new();
    hasher.input(&key_ipad[..]);
    hasher.input(data);
    let inner_hash: Vec<_> = hasher.result().into_iter().collect();

    let mut hasher = Sha512::new();
    hasher.input(&key_opad[..]);
    hasher.input(&inner_hash);
    hasher.result().into_iter().collect()
}

/// XOR byte slices of the same length and return the result as Vec<u8>
fn xor_bytes(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    assert_eq!(lhs.len(), rhs.len());
    let mut result = Vec::new();
    for i in 0..lhs.len() {
        result.push(lhs[i] ^ rhs[i]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use util::decode_hex;

    #[test]
    fn hmac_sha512_tv1() {
        const TEST_DATA: [u8; 8] = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65];
        const TEST_KEY: [u8; 20] = [0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b];
        const TEST_RESULT: [u8; 64] = [0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54];
        let result = hmac_sha512(&TEST_DATA[..], &TEST_KEY[..]);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn hmac_sha512_tv2() {
        const TEST_DATA: [u8; 28] = [0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f];
        const TEST_KEY: [u8; 4] = [0x4a, 0x65, 0x66, 0x65];
        const TEST_RESULT: [u8; 64] = [0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37];
        let result = hmac_sha512(&TEST_DATA[..], &TEST_KEY[..]);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn hmac_sha512_tv3() {
        const TEST_DATA: [u8; 50] = [0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd];
        const TEST_KEY: [u8; 20] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
        const TEST_RESULT: [u8; 64] = [0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84, 0xef, 0xb0, 0xf0, 0x75, 0x6c, 0x89, 0x0b, 0xe9, 0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36, 0x55, 0xf8, 0x3e, 0x33, 0xb2, 0x27, 0x9d, 0x39, 0xbf, 0x3e, 0x84, 0x82, 0x79, 0xa7, 0x22, 0xc8, 0x06, 0xb4, 0x85, 0xa4, 0x7e, 0x67, 0xc8, 0x07, 0xb9, 0x46, 0xa3, 0x37, 0xbe, 0xe8, 0x94, 0x26, 0x74, 0x27, 0x88, 0x59, 0xe1, 0x32, 0x92, 0xfb];
        let result = hmac_sha512(&TEST_DATA[..], &TEST_KEY[..]);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn hmac_sha512_tv4() {
        const TEST_DATA: [u8; 50] = [0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd];
        const TEST_KEY: [u8; 25] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19];
        const TEST_RESULT: [u8; 64] = [0xb0, 0xba, 0x46, 0x56, 0x37, 0x45, 0x8c, 0x69, 0x90, 0xe5, 0xa8, 0xc5, 0xf6, 0x1d, 0x4a, 0xf7, 0xe5, 0x76, 0xd9, 0x7f, 0xf9, 0x4b, 0x87, 0x2d, 0xe7, 0x6f, 0x80, 0x50, 0x36, 0x1e, 0xe3, 0xdb, 0xa9, 0x1c, 0xa5, 0xc1, 0x1a, 0xa2, 0x5e, 0xb4, 0xd6, 0x79, 0x27, 0x5c, 0xc5, 0x78, 0x80, 0x63, 0xa5, 0xf1, 0x97, 0x41, 0x12, 0x0c, 0x4f, 0x2d, 0xe2, 0xad, 0xeb, 0xeb, 0x10, 0xa2, 0x98, 0xdd];
        let result = hmac_sha512(&TEST_DATA[..], &TEST_KEY[..]);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn hmac_sha512_tv5() {
        const TEST_DATA: [u8; 54] = [0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x2d, 0x20, 0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x46, 0x69, 0x72, 0x73, 0x74];
        const TEST_KEY: [u8; 131] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
        const TEST_RESULT: [u8; 64] = [0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb, 0xb7, 0x14, 0x93, 0xc1, 0xdd, 0x7b, 0xe8, 0xb4, 0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1, 0x12, 0x1b, 0x01, 0x37, 0x83, 0xf8, 0xf3, 0x52, 0x6b, 0x56, 0xd0, 0x37, 0xe0, 0x5f, 0x25, 0x98, 0xbd, 0x0f, 0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52, 0x95, 0xe6, 0x4f, 0x73, 0xf6, 0x3f, 0x0a, 0xec, 0x8b, 0x91, 0x5a, 0x98, 0x5d, 0x78, 0x65, 0x98];
        let result = hmac_sha512(&TEST_DATA[..], &TEST_KEY[..]);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn hmac_sha512_tv6() {
        const TEST_DATA: [u8; 152] = [0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x20, 0x54, 0x68, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x6e, 0x65, 0x65, 0x64, 0x73, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x20, 0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x62, 0x65, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x65, 0x20, 0x48, 0x4d, 0x41, 0x43, 0x20, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e];
        const TEST_KEY: [u8; 131] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
        const TEST_RESULT: [u8; 64] = [0xe3, 0x7b, 0x6a, 0x77, 0x5d, 0xc8, 0x7d, 0xba, 0xa4, 0xdf, 0xa9, 0xf9, 0x6e, 0x5e, 0x3f, 0xfd, 0xde, 0xbd, 0x71, 0xf8, 0x86, 0x72, 0x89, 0x86, 0x5d, 0xf5, 0xa3, 0x2d, 0x20, 0xcd, 0xc9, 0x44, 0xb6, 0x02, 0x2c, 0xac, 0x3c, 0x49, 0x82, 0xb1, 0x0d, 0x5e, 0xeb, 0x55, 0xc3, 0xe4, 0xde, 0x15, 0x13, 0x46, 0x76, 0xfb, 0x6d, 0xe0, 0x44, 0x60, 0x65, 0xc9, 0x74, 0x40, 0xfa, 0x8c, 0x6a, 0x58];
        let result = hmac_sha512(&TEST_DATA[..], &TEST_KEY[..]);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn pbkdf2_tv1() {
        let test_password: Vec<u8> = "password".bytes().collect();
        let test_salt: Vec<u8> = "salt".bytes().collect();
        const TEST_RESULT: [u8; 64] = [0x86, 0x7f, 0x70, 0xcf, 0x1a, 0xde, 0x02, 0xcf, 0xf3, 0x75, 0x25, 0x99, 0xa3, 0xa5, 0x3d, 0xc4, 0xaf, 0x34, 0xc7, 0xa6, 0x69, 0x81, 0x5a, 0xe5, 0xd5, 0x13, 0x55, 0x4e, 0x1c, 0x8c, 0xf2, 0x52, 0xc0, 0x2d, 0x47, 0x0a, 0x28, 0x5a, 0x05, 0x01, 0xba, 0xd9, 0x99, 0xbf, 0xe9, 0x43, 0xc0, 0x8f, 0x05, 0x02, 0x35, 0xd7, 0xd6, 0x8b, 0x1d, 0xa5, 0x5e, 0x63, 0xf7, 0x3b, 0x60, 0xa5, 0x7f, 0xce];
        let result = pbkdf2(&test_password, &test_salt, 1);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn pbkdf2_tv2() {
        let test_password: Vec<u8> = "password".bytes().collect();
        let test_salt: Vec<u8> = "salt".bytes().collect();
        const TEST_RESULT: [u8; 64] = [0xe1, 0xd9, 0xc1, 0x6a, 0xa6, 0x81, 0x70, 0x8a, 0x45, 0xf5, 0xc7, 0xc4, 0xe2, 0x15, 0xce, 0xb6, 0x6e, 0x01, 0x1a, 0x2e, 0x9f, 0x00, 0x40, 0x71, 0x3f, 0x18, 0xae, 0xfd, 0xb8, 0x66, 0xd5, 0x3c, 0xf7, 0x6c, 0xab, 0x28, 0x68, 0xa3, 0x9b, 0x9f, 0x78, 0x40, 0xed, 0xce, 0x4f, 0xef, 0x5a, 0x82, 0xbe, 0x67, 0x33, 0x5c, 0x77, 0xa6, 0x06, 0x8e, 0x04, 0x11, 0x27, 0x54, 0xf2, 0x7c, 0xcf, 0x4e];
        let result = pbkdf2(&test_password, &test_salt, 2);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn pbkdf2_tv3() {
        let test_password: Vec<u8> = "password".bytes().collect();
        let test_salt: Vec<u8> = "salt".bytes().collect();
        const TEST_RESULT: [u8; 64] = [0xd1, 0x97, 0xb1, 0xb3, 0x3d, 0xb0, 0x14, 0x3e, 0x01, 0x8b, 0x12, 0xf3, 0xd1, 0xd1, 0x47, 0x9e, 0x6c, 0xde, 0xbd, 0xcc, 0x97, 0xc5, 0xc0, 0xf8, 0x7f, 0x69, 0x02, 0xe0, 0x72, 0xf4, 0x57, 0xb5, 0x14, 0x3f, 0x30, 0x60, 0x26, 0x41, 0xb3, 0xd5, 0x5c, 0xd3, 0x35, 0x98, 0x8c, 0xb3, 0x6b, 0x84, 0x37, 0x60, 0x60, 0xec, 0xd5, 0x32, 0xe0, 0x39, 0xb7, 0x42, 0xa2, 0x39, 0x43, 0x4a, 0xf2, 0xd5];
        let result = pbkdf2(&test_password, &test_salt, 4096);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn pbkdf2_tv4() {
        let test_password: Vec<u8> = "passwordPASSWORDpassword".bytes().collect();
        let test_salt: Vec<u8> = "saltSALTsaltSALTsaltSALTsaltSALTsalt".bytes().collect();
        const TEST_RESULT: [u8; 64] = [0x8c, 0x05, 0x11, 0xf4, 0xc6, 0xe5, 0x97, 0xc6, 0xac, 0x63, 0x15, 0xd8, 0xf0, 0x36, 0x2e, 0x22, 0x5f, 0x3c, 0x50, 0x14, 0x95, 0xba, 0x23, 0xb8, 0x68, 0xc0, 0x05, 0x17, 0x4d, 0xc4, 0xee, 0x71, 0x11, 0x5b, 0x59, 0xf9, 0xe6, 0x0c, 0xd9, 0x53, 0x2f, 0xa3, 0x3e, 0x0f, 0x75, 0xae, 0xfe, 0x30, 0x22, 0x5c, 0x58, 0x3a, 0x18, 0x6c, 0xd8, 0x2b, 0xd4, 0xda, 0xea, 0x97, 0x24, 0xa3, 0xd3, 0xb8];
        let result = pbkdf2(&test_password, &test_salt, 4096);
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn test_vectors() {
        let test_vectors = include!("test_vectors.in");
        assert_eq!(test_vectors.len() % 3, 0);
        for i in 0..test_vectors.len()/3 {
            let test_entropy = decode_hex(test_vectors[3*i + 0]).unwrap();
            let test_mnemonic = test_vectors[3*i + 1].to_string();
            let test_seed = decode_hex(test_vectors[3*i + 2]).unwrap();
            assert_eq!(test_entropy, mnemonic_to_entropy(&test_mnemonic).unwrap());
            assert_eq!(test_mnemonic, entropy_to_mnemonic(&test_entropy).unwrap());
            assert_eq!(test_seed, mnemonic_to_seed(&test_mnemonic, Some("TREZOR")));
        }
    }
}

