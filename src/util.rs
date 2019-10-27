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