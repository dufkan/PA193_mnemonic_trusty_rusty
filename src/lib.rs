use sha2::{Sha256, Sha512, Digest};


// get position of word in wordlist
fn mnemonic_lookup(mnemonic: &str, words: &Vec<&str>) -> u16 {
    match words.iter().position(|x| x == &mnemonic) {
        None => {
            panic!("Invalid word: {}", mnemonic)
        }
        Some(v) => {
            v as u16
        }
    }
}

// compute sha256 of input
fn sha256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(input);
    hasher.result().into_iter().collect()
}

// get checksum by entropy in bytes
fn checksum(entropy: &[u8]) -> u8 {
    let ent = entropy.len(); // number of bytes
    assert_eq!(ent%4, 0); // entropy must be a multiple of 4 bytes
    let cs = ent/4;
    let header = sha256(entropy)[0]; // first byte of hash
    match cs {
        4 => header & 0b1111_0000,
        5 => header & 0b1111_1000,
        6 => header & 0b1111_1100,
        7 => header & 0b1111_1110,
        8 => header,
        _ => panic!("Size of the block is not compatible!{}", cs),
        }
    }

// get n-th word of entropy ... todo words should be const global variable
fn get_word<'a>(position: usize, entropy: &Vec<u8>, words: &Vec<&'a str>) -> &'a str {
    let mut index: u16 = 0b0000_0000_0000_0000; // n-th mnemonic word of sentence
    let mut byte: usize; // n-th byte of entropy
    let mut bit: usize; // nt-th bit of byte
    let mut bit_value: bool; // value of bit
    let first_bit: usize = position * 11; // first bit of mnemonic word

    // compute each bit of mnemonic word
    for offset in 0..11 {
        byte = (first_bit + offset) / 8;
        bit = (first_bit + offset) % 8;
        // println!("byte: {}, bit: {}", entropy[byte], bit) ;
        bit_value = (entropy[byte] & (128u8 >> bit) as u8) != 0u8;
        if bit_value {
            index |= (1024 >> offset) as u16;
        }
    }
    // println!("index {}", index);
    words[index as usize]
}

// get words from entropy
pub fn entropy_to_mnemonic(init_entropy: &[u8]) -> String {
    let mut entropy: Vec<_> = init_entropy.to_vec();
    let word_list: Vec<_> = RAW_WORDS.to_vec();
    entropy.push(checksum(init_entropy)); // append checksum to the end of entropy
    let ms = init_entropy.len() * 3 / 4; // length of mnemonic sentence is 0.75 multiply of initial entropy
    let mut result = String::new();
    for index in 0..ms {
        result.push_str(get_word(index, &entropy, &word_list));
        if index != ms-1 {
            result.push_str(" ");
        }
    }
    result
}

pub fn mnemonic_to_entropy(sentence: String) -> Vec<u8> {
    let word_list: Vec<_> = RAW_WORDS.to_vec();
    let words: Vec<_> = sentence.split(" ").collect();
    let mut index: u16;
    let mut result: [u8; 33] = [0; 33];
    let mut pos = 0usize; // position of actual bit in entropy
    let mut bit_value: bool;
    for word in words {
        index = mnemonic_lookup(word, &word_list);
        for offset in 0..11 {
            bit_value = (index & (1024 >> offset as u16)) != 0u16;
            if bit_value {
                result[pos/8] |= (128u8 >> pos%8) as u8;
            }
            pos += 1;
        }
    }
    let checksum_len = pos/33;
    let entropy = (&result[0 .. (pos - checksum_len)/8]).to_vec();
    let checksum = checksum(&entropy);
    println!("checksum = {}", checksum);
    // check if checksum is equal to last byte
    assert_eq!(checksum, result[(pos - checksum_len)/8]);
    entropy
}

pub fn init() {
    // initial params
    let v = b"0123456789abcdef".to_vec();
    let words: Vec<_> = RAW_WORDS.to_vec();
    // tests
    println!("Position of \"zoo\" in list: {}", mnemonic_lookup("zoo", &words));
    println!("5-th word in the sentence: {}", get_word(5usize, &v, &words)); // indexed by 0
    println!("appendix of the entropy: {}", checksum(&v));

    let sentence: String = entropy_to_mnemonic(&v);
    println!("The final sentence: {} ", sentence);
    let entropy: Vec<u8> = mnemonic_to_entropy(sentence);
    print!("Entropy of the sentence:");
    for x in entropy { print!(" {}", x); }
}

pub fn seed(mnemonic: &str, passphrase: Option<&str>) -> Vec<u8> {
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
    fn seed_tv1() {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const TEST_RESULT: [u8; 64] = [0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05, 0xed, 0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e, 0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34, 0x95, 0x53, 0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82, 0x64, 0xc1, 0xe1, 0xc9, 0x2f, 0x2c, 0xf1, 0x41, 0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b, 0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04];
        let result = seed(test_mnemonic, Some("TREZOR"));
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn seed_tv2() {
        let test_mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        const TEST_RESULT: [u8; 64] = [0x2e, 0x89, 0x05, 0x81, 0x9b, 0x87, 0x23, 0xfe, 0x2c, 0x1d, 0x16, 0x18, 0x60, 0xe5, 0xee, 0x18, 0x30, 0x31, 0x8d, 0xbf, 0x49, 0xa8, 0x3b, 0xd4, 0x51, 0xcf, 0xb8, 0x44, 0x0c, 0x28, 0xbd, 0x6f, 0xa4, 0x57, 0xfe, 0x12, 0x96, 0x10, 0x65, 0x59, 0xa3, 0xc8, 0x09, 0x37, 0xa1, 0xc1, 0x06, 0x9b, 0xe3, 0xa3, 0xa5, 0xbd, 0x38, 0x1e, 0xe6, 0x26, 0x0e, 0x8d, 0x97, 0x39, 0xfc, 0xe1, 0xf6, 0x07];
        let result = seed(test_mnemonic, Some("TREZOR"));
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn seed_tv3() {
        let test_mnemonic = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
        const TEST_RESULT: [u8; 64] = [0x01, 0xf5, 0xbc, 0xed, 0x59, 0xde, 0xc4, 0x8e, 0x36, 0x2f, 0x2c, 0x45, 0xb5, 0xde, 0x68, 0xb9, 0xfd, 0x6c, 0x92, 0xc6, 0x63, 0x4f, 0x44, 0xd6, 0xd4, 0x0a, 0xab, 0x69, 0x05, 0x65, 0x06, 0xf0, 0xe3, 0x55, 0x24, 0xa5, 0x18, 0x03, 0x4d, 0xdc, 0x11, 0x92, 0xe1, 0xda, 0xcd, 0x32, 0xc1, 0xed, 0x3e, 0xaa, 0x3c, 0x3b, 0x13, 0x1c, 0x88, 0xed, 0x8e, 0x7e, 0x54, 0xc4, 0x9a, 0x5d, 0x09, 0x98];
        let result = seed(test_mnemonic, Some("TREZOR"));
        assert_eq!(result[..], TEST_RESULT[..]);
    }

    #[test]
    fn entropy_to_mnemonic_tv1() {
        let test_entropy = [0b0000_0000;16].to_vec();
        let test_result: String = String::from("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let result = entropy_to_mnemonic(&test_entropy);
        assert_eq!(result, test_result);
    }
}


const RAW_WORDS: [&'static str; 2048] = [
    "abandon",  "ability",  "able",     "about",    "above",    "absent",
    "absorb",   "abstract", "absurd",   "abuse",    "access",   "accident",
    "account",  "accuse",   "achieve",  "acid",     "acoustic", "acquire",
    "across",   "act",      "action",   "actor",    "actress",  "actual",
    "adapt",    "add",      "addict",   "address",  "adjust",   "admit",
    "adult",    "advance",  "advice",   "aerobic",  "affair",   "afford",
    "afraid",   "again",    "age",      "agent",    "agree",    "ahead",
    "aim",      "air",      "airport",  "aisle",    "alarm",    "album",
    "alcohol",  "alert",    "alien",    "all",      "alley",    "allow",
    "almost",   "alone",    "alpha",    "already",  "also",     "alter",
    "always",   "amateur",  "amazing",  "among",    "amount",   "amused",
    "analyst",  "anchor",   "ancient",  "anger",    "angle",    "angry",
    "animal",   "ankle",    "announce", "annual",   "another",  "answer",
    "antenna",  "antique",  "anxiety",  "any",      "apart",    "apology",
    "appear",   "apple",    "approve",  "april",    "arch",     "arctic",
    "area",     "arena",    "argue",    "arm",      "armed",    "armor",
    "army",     "around",   "arrange",  "arrest",   "arrive",   "arrow",
    "art",      "artefact", "artist",   "artwork",  "ask",      "aspect",
    "assault",  "asset",    "assist",   "assume",   "asthma",   "athlete",
    "atom",     "attack",   "attend",   "attitude", "attract",  "auction",
    "audit",    "august",   "aunt",     "author",   "auto",     "autumn",
    "average",  "avocado",  "avoid",    "awake",    "aware",    "away",
    "awesome",  "awful",    "awkward",  "axis",     "baby",     "bachelor",
    "bacon",    "badge",    "bag",      "balance",  "balcony",  "ball",
    "bamboo",   "banana",   "banner",   "bar",      "barely",   "bargain",
    "barrel",   "base",     "basic",    "basket",   "battle",   "beach",
    "bean",     "beauty",   "because",  "become",   "beef",     "before",
    "begin",    "behave",   "behind",   "believe",  "below",    "belt",
    "bench",    "benefit",  "best",     "betray",   "better",   "between",
    "beyond",   "bicycle",  "bid",      "bike",     "bind",     "biology",
    "bird",     "birth",    "bitter",   "black",    "blade",    "blame",
    "blanket",  "blast",    "bleak",    "bless",    "blind",    "blood",
    "blossom",  "blouse",   "blue",     "blur",     "blush",    "board",
    "boat",     "body",     "boil",     "bomb",     "bone",     "bonus",
    "book",     "boost",    "border",   "boring",   "borrow",   "boss",
    "bottom",   "bounce",   "box",      "boy",      "bracket",  "brain",
    "brand",    "brass",    "brave",    "bread",    "breeze",   "brick",
    "bridge",   "brief",    "bright",   "bring",    "brisk",    "broccoli",
    "broken",   "bronze",   "broom",    "brother",  "brown",    "brush",
    "bubble",   "buddy",    "budget",   "buffalo",  "build",    "bulb",
    "bulk",     "bullet",   "bundle",   "bunker",   "burden",   "burger",
    "burst",    "bus",      "business", "busy",     "butter",   "buyer",
    "buzz",     "cabbage",  "cabin",    "cable",    "cactus",   "cage",
    "cake",     "call",     "calm",     "camera",   "camp",     "can",
    "canal",    "cancel",   "candy",    "cannon",   "canoe",    "canvas",
    "canyon",   "capable",  "capital",  "captain",  "car",      "carbon",
    "card",     "cargo",    "carpet",   "carry",    "cart",     "case",
    "cash",     "casino",   "castle",   "casual",   "cat",      "catalog",
    "catch",    "category", "cattle",   "caught",   "cause",    "caution",
    "cave",     "ceiling",  "celery",   "cement",   "census",   "century",
    "cereal",   "certain",  "chair",    "chalk",    "champion", "change",
    "chaos",    "chapter",  "charge",   "chase",    "chat",     "cheap",
    "check",    "cheese",   "chef",     "cherry",   "chest",    "chicken",
    "chief",    "child",    "chimney",  "choice",   "choose",   "chronic",
    "chuckle",  "chunk",    "churn",    "cigar",    "cinnamon", "circle",
    "citizen",  "city",     "civil",    "claim",    "clap",     "clarify",
    "claw",     "clay",     "clean",    "clerk",    "clever",   "click",
    "client",   "cliff",    "climb",    "clinic",   "clip",     "clock",
    "clog",     "close",    "cloth",    "cloud",    "clown",    "club",
    "clump",    "cluster",  "clutch",   "coach",    "coast",    "coconut",
    "code",     "coffee",   "coil",     "coin",     "collect",  "color",
    "column",   "combine",  "come",     "comfort",  "comic",    "common",
    "company",  "concert",  "conduct",  "confirm",  "congress", "connect",
    "consider", "control",  "convince", "cook",     "cool",     "copper",
    "copy",     "coral",    "core",     "corn",     "correct",  "cost",
    "cotton",   "couch",    "country",  "couple",   "course",   "cousin",
    "cover",    "coyote",   "crack",    "cradle",   "craft",    "cram",
    "crane",    "crash",    "crater",   "crawl",    "crazy",    "cream",
    "credit",   "creek",    "crew",     "cricket",  "crime",    "crisp",
    "critic",   "crop",     "cross",    "crouch",   "crowd",    "crucial",
    "cruel",    "cruise",   "crumble",  "crunch",   "crush",    "cry",
    "crystal",  "cube",     "culture",  "cup",      "cupboard", "curious",
    "current",  "curtain",  "curve",    "cushion",  "custom",   "cute",
    "cycle",    "dad",      "damage",   "damp",     "dance",    "danger",
    "daring",   "dash",     "daughter", "dawn",     "day",      "deal",
    "debate",   "debris",   "decade",   "december", "decide",   "decline",
    "decorate", "decrease", "deer",     "defense",  "define",   "defy",
    "degree",   "delay",    "deliver",  "demand",   "demise",   "denial",
    "dentist",  "deny",     "depart",   "depend",   "deposit",  "depth",
    "deputy",   "derive",   "describe", "desert",   "design",   "desk",
    "despair",  "destroy",  "detail",   "detect",   "develop",  "device",
    "devote",   "diagram",  "dial",     "diamond",  "diary",    "dice",
    "diesel",   "diet",     "differ",   "digital",  "dignity",  "dilemma",
    "dinner",   "dinosaur", "direct",   "dirt",     "disagree", "discover",
    "disease",  "dish",     "dismiss",  "disorder", "display",  "distance",
    "divert",   "divide",   "divorce",  "dizzy",    "doctor",   "document",
    "dog",      "doll",     "dolphin",  "domain",   "donate",   "donkey",
    "donor",    "door",     "dose",     "double",   "dove",     "draft",
    "dragon",   "drama",    "drastic",  "draw",     "dream",    "dress",
    "drift",    "drill",    "drink",    "drip",     "drive",    "drop",
    "drum",     "dry",      "duck",     "dumb",     "dune",     "during",
    "dust",     "dutch",    "duty",     "dwarf",    "dynamic",  "eager",
    "eagle",    "early",    "earn",     "earth",    "easily",   "east",
    "easy",     "echo",     "ecology",  "economy",  "edge",     "edit",
    "educate",  "effort",   "egg",      "eight",    "either",   "elbow",
    "elder",    "electric", "elegant",  "element",  "elephant", "elevator",
    "elite",    "else",     "embark",   "embody",   "embrace",  "emerge",
    "emotion",  "employ",   "empower",  "empty",    "enable",   "enact",
    "end",      "endless",  "endorse",  "enemy",    "energy",   "enforce",
    "engage",   "engine",   "enhance",  "enjoy",    "enlist",   "enough",
    "enrich",   "enroll",   "ensure",   "enter",    "entire",   "entry",
    "envelope", "episode",  "equal",    "equip",    "era",      "erase",
    "erode",    "erosion",  "error",    "erupt",    "escape",   "essay",
    "essence",  "estate",   "eternal",  "ethics",   "evidence", "evil",
    "evoke",    "evolve",   "exact",    "example",  "excess",   "exchange",
    "excite",   "exclude",  "excuse",   "execute",  "exercise", "exhaust",
    "exhibit",  "exile",    "exist",    "exit",     "exotic",   "expand",
    "expect",   "expire",   "explain",  "expose",   "express",  "extend",
    "extra",    "eye",      "eyebrow",  "fabric",   "face",     "faculty",
    "fade",     "faint",    "faith",    "fall",     "false",    "fame",
    "family",   "famous",   "fan",      "fancy",    "fantasy",  "farm",
    "fashion",  "fat",      "fatal",    "father",   "fatigue",  "fault",
    "favorite", "feature",  "february", "federal",  "fee",      "feed",
    "feel",     "female",   "fence",    "festival", "fetch",    "fever",
    "few",      "fiber",    "fiction",  "field",    "figure",   "file",
    "film",     "filter",   "final",    "find",     "fine",     "finger",
    "finish",   "fire",     "firm",     "first",    "fiscal",   "fish",
    "fit",      "fitness",  "fix",      "flag",     "flame",    "flash",
    "flat",     "flavor",   "flee",     "flight",   "flip",     "float",
    "flock",    "floor",    "flower",   "fluid",    "flush",    "fly",
    "foam",     "focus",    "fog",      "foil",     "fold",     "follow",
    "food",     "foot",     "force",    "forest",   "forget",   "fork",
    "fortune",  "forum",    "forward",  "fossil",   "foster",   "found",
    "fox",      "fragile",  "frame",    "frequent", "fresh",    "friend",
    "fringe",   "frog",     "front",    "frost",    "frown",    "frozen",
    "fruit",    "fuel",     "fun",      "funny",    "furnace",  "fury",
    "future",   "gadget",   "gain",     "galaxy",   "gallery",  "game",
    "gap",      "garage",   "garbage",  "garden",   "garlic",   "garment",
    "gas",      "gasp",     "gate",     "gather",   "gauge",    "gaze",
    "general",  "genius",   "genre",    "gentle",   "genuine",  "gesture",
    "ghost",    "giant",    "gift",     "giggle",   "ginger",   "giraffe",
    "girl",     "give",     "glad",     "glance",   "glare",    "glass",
    "glide",    "glimpse",  "globe",    "gloom",    "glory",    "glove",
    "glow",     "glue",     "goat",     "goddess",  "gold",     "good",
    "goose",    "gorilla",  "gospel",   "gossip",   "govern",   "gown",
    "grab",     "grace",    "grain",    "grant",    "grape",    "grass",
    "gravity",  "great",    "green",    "grid",     "grief",    "grit",
    "grocery",  "group",    "grow",     "grunt",    "guard",    "guess",
    "guide",    "guilt",    "guitar",   "gun",      "gym",      "habit",
    "hair",     "half",     "hammer",   "hamster",  "hand",     "happy",
    "harbor",   "hard",     "harsh",    "harvest",  "hat",      "have",
    "hawk",     "hazard",   "head",     "health",   "heart",    "heavy",
    "hedgehog", "height",   "hello",    "helmet",   "help",     "hen",
    "hero",     "hidden",   "high",     "hill",     "hint",     "hip",
    "hire",     "history",  "hobby",    "hockey",   "hold",     "hole",
    "holiday",  "hollow",   "home",     "honey",    "hood",     "hope",
    "horn",     "horror",   "horse",    "hospital", "host",     "hotel",
    "hour",     "hover",    "hub",      "huge",     "human",    "humble",
    "humor",    "hundred",  "hungry",   "hunt",     "hurdle",   "hurry",
    "hurt",     "husband",  "hybrid",   "ice",      "icon",     "idea",
    "identify", "idle",     "ignore",   "ill",      "illegal",  "illness",
    "image",    "imitate",  "immense",  "immune",   "impact",   "impose",
    "improve",  "impulse",  "inch",     "include",  "income",   "increase",
    "index",    "indicate", "indoor",   "industry", "infant",   "inflict",
    "inform",   "inhale",   "inherit",  "initial",  "inject",   "injury",
    "inmate",   "inner",    "innocent", "input",    "inquiry",  "insane",
    "insect",   "inside",   "inspire",  "install",  "intact",   "interest",
    "into",     "invest",   "invite",   "involve",  "iron",     "island",
    "isolate",  "issue",    "item",     "ivory",    "jacket",   "jaguar",
    "jar",      "jazz",     "jealous",  "jeans",    "jelly",    "jewel",
    "job",      "join",     "joke",     "journey",  "joy",      "judge",
    "juice",    "jump",     "jungle",   "junior",   "junk",     "just",
    "kangaroo", "keen",     "keep",     "ketchup",  "key",      "kick",
    "kid",      "kidney",   "kind",     "kingdom",  "kiss",     "kit",
    "kitchen",  "kite",     "kitten",   "kiwi",     "knee",     "knife",
    "knock",    "know",     "lab",      "label",    "labor",    "ladder",
    "lady",     "lake",     "lamp",     "language", "laptop",   "large",
    "later",    "latin",    "laugh",    "laundry",  "lava",     "law",
    "lawn",     "lawsuit",  "layer",    "lazy",     "leader",   "leaf",
    "learn",    "leave",    "lecture",  "left",     "leg",      "legal",
    "legend",   "leisure",  "lemon",    "lend",     "length",   "lens",
    "leopard",  "lesson",   "letter",   "level",    "liar",     "liberty",
    "library",  "license",  "life",     "lift",     "light",    "like",
    "limb",     "limit",    "link",     "lion",     "liquid",   "list",
    "little",   "live",     "lizard",   "load",     "loan",     "lobster",
    "local",    "lock",     "logic",    "lonely",   "long",     "loop",
    "lottery",  "loud",     "lounge",   "love",     "loyal",    "lucky",
    "luggage",  "lumber",   "lunar",    "lunch",    "luxury",   "lyrics",
    "machine",  "mad",      "magic",    "magnet",   "maid",     "mail",
    "main",     "major",    "make",     "mammal",   "man",      "manage",
    "mandate",  "mango",    "mansion",  "manual",   "maple",    "marble",
    "march",    "margin",   "marine",   "market",   "marriage", "mask",
    "mass",     "master",   "match",    "material", "math",     "matrix",
    "matter",   "maximum",  "maze",     "meadow",   "mean",     "measure",
    "meat",     "mechanic", "medal",    "media",    "melody",   "melt",
    "member",   "memory",   "mention",  "menu",     "mercy",    "merge",
    "merit",    "merry",    "mesh",     "message",  "metal",    "method",
    "middle",   "midnight", "milk",     "million",  "mimic",    "mind",
    "minimum",  "minor",    "minute",   "miracle",  "mirror",   "misery",
    "miss",     "mistake",  "mix",      "mixed",    "mixture",  "mobile",
    "model",    "modify",   "mom",      "moment",   "monitor",  "monkey",
    "monster",  "month",    "moon",     "moral",    "more",     "morning",
    "mosquito", "mother",   "motion",   "motor",    "mountain", "mouse",
    "move",     "movie",    "much",     "muffin",   "mule",     "multiply",
    "muscle",   "museum",   "mushroom", "music",    "must",     "mutual",
    "myself",   "mystery",  "myth",     "naive",    "name",     "napkin",
    "narrow",   "nasty",    "nation",   "nature",   "near",     "neck",
    "need",     "negative", "neglect",  "neither",  "nephew",   "nerve",
    "nest",     "net",      "network",  "neutral",  "never",    "news",
    "next",     "nice",     "night",    "noble",    "noise",    "nominee",
    "noodle",   "normal",   "north",    "nose",     "notable",  "note",
    "nothing",  "notice",   "novel",    "now",      "nuclear",  "number",
    "nurse",    "nut",      "oak",      "obey",     "object",   "oblige",
    "obscure",  "observe",  "obtain",   "obvious",  "occur",    "ocean",
    "october",  "odor",     "off",      "offer",    "office",   "often",
    "oil",      "okay",     "old",      "olive",    "olympic",  "omit",
    "once",     "one",      "onion",    "online",   "only",     "open",
    "opera",    "opinion",  "oppose",   "option",   "orange",   "orbit",
    "orchard",  "order",    "ordinary", "organ",    "orient",   "original",
    "orphan",   "ostrich",  "other",    "outdoor",  "outer",    "output",
    "outside",  "oval",     "oven",     "over",     "own",      "owner",
    "oxygen",   "oyster",   "ozone",    "pact",     "paddle",   "page",
    "pair",     "palace",   "palm",     "panda",    "panel",    "panic",
    "panther",  "paper",    "parade",   "parent",   "park",     "parrot",
    "party",    "pass",     "patch",    "path",     "patient",  "patrol",
    "pattern",  "pause",    "pave",     "payment",  "peace",    "peanut",
    "pear",     "peasant",  "pelican",  "pen",      "penalty",  "pencil",
    "people",   "pepper",   "perfect",  "permit",   "person",   "pet",
    "phone",    "photo",    "phrase",   "physical", "piano",    "picnic",
    "picture",  "piece",    "pig",      "pigeon",   "pill",     "pilot",
    "pink",     "pioneer",  "pipe",     "pistol",   "pitch",    "pizza",
    "place",    "planet",   "plastic",  "plate",    "play",     "please",
    "pledge",   "pluck",    "plug",     "plunge",   "poem",     "poet",
    "point",    "polar",    "pole",     "police",   "pond",     "pony",
    "pool",     "popular",  "portion",  "position", "possible", "post",
    "potato",   "pottery",  "poverty",  "powder",   "power",    "practice",
    "praise",   "predict",  "prefer",   "prepare",  "present",  "pretty",
    "prevent",  "price",    "pride",    "primary",  "print",    "priority",
    "prison",   "private",  "prize",    "problem",  "process",  "produce",
    "profit",   "program",  "project",  "promote",  "proof",    "property",
    "prosper",  "protect",  "proud",    "provide",  "public",   "pudding",
    "pull",     "pulp",     "pulse",    "pumpkin",  "punch",    "pupil",
    "puppy",    "purchase", "purity",   "purpose",  "purse",    "push",
    "put",      "puzzle",   "pyramid",  "quality",  "quantum",  "quarter",
    "question", "quick",    "quit",     "quiz",     "quote",    "rabbit",
    "raccoon",  "race",     "rack",     "radar",    "radio",    "rail",
    "rain",     "raise",    "rally",    "ramp",     "ranch",    "random",
    "range",    "rapid",    "rare",     "rate",     "rather",   "raven",
    "raw",      "razor",    "ready",    "real",     "reason",   "rebel",
    "rebuild",  "recall",   "receive",  "recipe",   "record",   "recycle",
    "reduce",   "reflect",  "reform",   "refuse",   "region",   "regret",
    "regular",  "reject",   "relax",    "release",  "relief",   "rely",
    "remain",   "remember", "remind",   "remove",   "render",   "renew",
    "rent",     "reopen",   "repair",   "repeat",   "replace",  "report",
    "require",  "rescue",   "resemble", "resist",   "resource", "response",
    "result",   "retire",   "retreat",  "return",   "reunion",  "reveal",
    "review",   "reward",   "rhythm",   "rib",      "ribbon",   "rice",
    "rich",     "ride",     "ridge",    "rifle",    "right",    "rigid",
    "ring",     "riot",     "ripple",   "risk",     "ritual",   "rival",
    "river",    "road",     "roast",    "robot",    "robust",   "rocket",
    "romance",  "roof",     "rookie",   "room",     "rose",     "rotate",
    "rough",    "round",    "route",    "royal",    "rubber",   "rude",
    "rug",      "rule",     "run",      "runway",   "rural",    "sad",
    "saddle",   "sadness",  "safe",     "sail",     "salad",    "salmon",
    "salon",    "salt",     "salute",   "same",     "sample",   "sand",
    "satisfy",  "satoshi",  "sauce",    "sausage",  "save",     "say",
    "scale",    "scan",     "scare",    "scatter",  "scene",    "scheme",
    "school",   "science",  "scissors", "scorpion", "scout",    "scrap",
    "screen",   "script",   "scrub",    "sea",      "search",   "season",
    "seat",     "second",   "secret",   "section",  "security", "seed",
    "seek",     "segment",  "select",   "sell",     "seminar",  "senior",
    "sense",    "sentence", "series",   "service",  "session",  "settle",
    "setup",    "seven",    "shadow",   "shaft",    "shallow",  "share",
    "shed",     "shell",    "sheriff",  "shield",   "shift",    "shine",
    "ship",     "shiver",   "shock",    "shoe",     "shoot",    "shop",
    "short",    "shoulder", "shove",    "shrimp",   "shrug",    "shuffle",
    "shy",      "sibling",  "sick",     "side",     "siege",    "sight",
    "sign",     "silent",   "silk",     "silly",    "silver",   "similar",
    "simple",   "since",    "sing",     "siren",    "sister",   "situate",
    "six",      "size",     "skate",    "sketch",   "ski",      "skill",
    "skin",     "skirt",    "skull",    "slab",     "slam",     "sleep",
    "slender",  "slice",    "slide",    "slight",   "slim",     "slogan",
    "slot",     "slow",     "slush",    "small",    "smart",    "smile",
    "smoke",    "smooth",   "snack",    "snake",    "snap",     "sniff",
    "snow",     "soap",     "soccer",   "social",   "sock",     "soda",
    "soft",     "solar",    "soldier",  "solid",    "solution", "solve",
    "someone",  "song",     "soon",     "sorry",    "sort",     "soul",
    "sound",    "soup",     "source",   "south",    "space",    "spare",
    "spatial",  "spawn",    "speak",    "special",  "speed",    "spell",
    "spend",    "sphere",   "spice",    "spider",   "spike",    "spin",
    "spirit",   "split",    "spoil",    "sponsor",  "spoon",    "sport",
    "spot",     "spray",    "spread",   "spring",   "spy",      "square",
    "squeeze",  "squirrel", "stable",   "stadium",  "staff",    "stage",
    "stairs",   "stamp",    "stand",    "start",    "state",    "stay",
    "steak",    "steel",    "stem",     "step",     "stereo",   "stick",
    "still",    "sting",    "stock",    "stomach",  "stone",    "stool",
    "story",    "stove",    "strategy", "street",   "strike",   "strong",
    "struggle", "student",  "stuff",    "stumble",  "style",    "subject",
    "submit",   "subway",   "success",  "such",     "sudden",   "suffer",
    "sugar",    "suggest",  "suit",     "summer",   "sun",      "sunny",
    "sunset",   "super",    "supply",   "supreme",  "sure",     "surface",
    "surge",    "surprise", "surround", "survey",   "suspect",  "sustain",
    "swallow",  "swamp",    "swap",     "swarm",    "swear",    "sweet",
    "swift",    "swim",     "swing",    "switch",   "sword",    "symbol",
    "symptom",  "syrup",    "system",   "table",    "tackle",   "tag",
    "tail",     "talent",   "talk",     "tank",     "tape",     "target",
    "task",     "taste",    "tattoo",   "taxi",     "teach",    "team",
    "tell",     "ten",      "tenant",   "tennis",   "tent",     "term",
    "test",     "text",     "thank",    "that",     "theme",    "then",
    "theory",   "there",    "they",     "thing",    "this",     "thought",
    "three",    "thrive",   "throw",    "thumb",    "thunder",  "ticket",
    "tide",     "tiger",    "tilt",     "timber",   "time",     "tiny",
    "tip",      "tired",    "tissue",   "title",    "toast",    "tobacco",
    "today",    "toddler",  "toe",      "together", "toilet",   "token",
    "tomato",   "tomorrow", "tone",     "tongue",   "tonight",  "tool",
    "tooth",    "top",      "topic",    "topple",   "torch",    "tornado",
    "tortoise", "toss",     "total",    "tourist",  "toward",   "tower",
    "town",     "toy",      "track",    "trade",    "traffic",  "tragic",
    "train",    "transfer", "trap",     "trash",    "travel",   "tray",
    "treat",    "tree",     "trend",    "trial",    "tribe",    "trick",
    "trigger",  "trim",     "trip",     "trophy",   "trouble",  "truck",
    "true",     "truly",    "trumpet",  "trust",    "truth",    "try",
    "tube",     "tuition",  "tumble",   "tuna",     "tunnel",   "turkey",
    "turn",     "turtle",   "twelve",   "twenty",   "twice",    "twin",
    "twist",    "two",      "type",     "typical",  "ugly",     "umbrella",
    "unable",   "unaware",  "uncle",    "uncover",  "under",    "undo",
    "unfair",   "unfold",   "unhappy",  "uniform",  "unique",   "unit",
    "universe", "unknown",  "unlock",   "until",    "unusual",  "unveil",
    "update",   "upgrade",  "uphold",   "upon",     "upper",    "upset",
    "urban",    "urge",     "usage",    "use",      "used",     "useful",
    "useless",  "usual",    "utility",  "vacant",   "vacuum",   "vague",
    "valid",    "valley",   "valve",    "van",      "vanish",   "vapor",
    "various",  "vast",     "vault",    "vehicle",  "velvet",   "vendor",
    "venture",  "venue",    "verb",     "verify",   "version",  "very",
    "vessel",   "veteran",  "viable",   "vibrant",  "vicious",  "victory",
    "video",    "view",     "village",  "vintage",  "violin",   "virtual",
    "virus",    "visa",     "visit",    "visual",   "vital",    "vivid",
    "vocal",    "voice",    "void",     "volcano",  "volume",   "vote",
    "voyage",   "wage",     "wagon",    "wait",     "walk",     "wall",
    "walnut",   "want",     "warfare",  "warm",     "warrior",  "wash",
    "wasp",     "waste",    "water",    "wave",     "way",      "wealth",
    "weapon",   "wear",     "weasel",   "weather",  "web",      "wedding",
    "weekend",  "weird",    "welcome",  "west",     "wet",      "whale",
    "what",     "wheat",    "wheel",    "when",     "where",    "whip",
    "whisper",  "wide",     "width",    "wife",     "wild",     "will",
    "win",      "window",   "wine",     "wing",     "wink",     "winner",
    "winter",   "wire",     "wisdom",   "wise",     "wish",     "witness",
    "wolf",     "woman",    "wonder",   "wood",     "wool",     "word",
    "work",     "world",    "worry",    "worth",    "wrap",     "wreck",
    "wrestle",  "wrist",    "write",    "wrong",    "yard",     "year",
    "yellow",   "you",      "young",    "youth",    "zebra",    "zero",
    "zone",     "zoo"
    ];
