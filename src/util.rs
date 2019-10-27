use std::num::ParseIntError;

/// Checks whether given string is hexadecimal
pub fn is_hexadecimal(text: &str) -> bool {
    if text.len() % 2 == 1 {
        return false;
    }
    for character in text.chars() {
        if !character.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

// https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
pub fn decode_hex(input: &str) -> Result<Vec<u8>, ParseIntError> {
    if !is_hexadecimal(input) {
        panic!("Invalid input");
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16))
        .collect()
}

/// Checks whether given string is binary
pub fn is_binary(text: &str) -> bool {
    for character in text.chars() {
        if !(character == '0' || character == '1') {
            return false;
        }
    }
    true
}


/// Checks whether given string has only albhabetic or whitespace characters
pub fn is_alphabetic_whitespace(text: &str) -> bool{
    for character in text.chars() {
        if !(character.is_alphabetic() || character.is_whitespace()) {
            return false;
        }
    }
    true
}

/// Convert binary string to hex
pub fn binary_to_hex(val: &str) -> String {
    if val.len() % 8 != 0 {
        panic!("Invalid binary input - length not divisible by 8");
    }

    let mut result = String::new();
    let mut binary_text = val;
    for _ in 0..(binary_text.len() / 4) {
        let partial_result = &binary_text[..4];
        let partial_hex: u8 = u8::from_str_radix(partial_result, 2).unwrap();
        result.push_str(&format!("{:0x}", partial_hex));
        binary_text = &binary_text[4..];
    }
    result
}


#[cfg(test)]
mod tests {
    use super::*;

    # [test]
    fn test_is_binary_1() {
        assert_eq!(is_binary("0101010101011111110000011010"), true);
    }

    # [test]
    fn test_is_binary_2() {
        assert_eq!(is_binary("01010101010111111100000121010"), false);
    }

    # [test]
    fn test_is_binary_3() {
        assert_eq!(is_binary(""), true);
    }

    # [test]
    fn test_is_hexadecimal_1() {
        assert_eq!(is_hexadecimal("0101010101101011"), true);
    }

    # [test]
    fn test_is_hexadecimal_2() {
        assert_eq!(is_hexadecimal("02af02155ff02e6c9897d956b4"), true);
    }

    # [test]
    fn test_is_hexadecimal_3() {
        assert_eq!(is_hexadecimal("02af02155ff02e6c9897d956b45"), false);
    }

    # [test]
    fn test_is_hexadecimal_4() {
        assert_eq!(is_hexadecimal("02af02155ff02e6c9897d956b4x"), false);
    }

    # [test]
    fn test_is_alphabetic_whitespace_1() {
        assert_eq!(is_alphabetic_whitespace("02af02155ff02e6c9897d956b4x"), false);
    }

    # [test]
    fn test_is_alphabetic_whitespace_2() {
        assert_eq!(is_alphabetic_whitespace("sdaoashdiowoidwncadoej da sf s s"), true);
    }

    # [test]
    fn test_is_alphabetic_whitespace_3() {
        assert_eq!(is_alphabetic_whitespace("      "), true);
    }

    # [test]
    fn test_binary_to_hex_1() {
        assert_eq!(binary_to_hex("11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"), "ffffffffffffffffffffffffffffffff")
    }

    # [test]
    fn test_binary_to_hex_2() {
        assert_eq!(binary_to_hex("0000011001101101110010100001101000101011101101111110100010100001110110110010100000110010000101001000110011101001100100110011111011101010000011110011101011001001010101001000110101111001001100010001001011011001101010010101110010010100000001111110111110101101"), "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad")
    }

    # [test]
    fn test_binary_to_hex_3() {
        assert_eq!(binary_to_hex("11000000101110100101101010001110100100010100000100010001001000010000111100101011110100010011000111110011110101011110000010001101"), "c0ba5a8e914111210f2bd131f3d5e08d");
    }
}