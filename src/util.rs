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
}