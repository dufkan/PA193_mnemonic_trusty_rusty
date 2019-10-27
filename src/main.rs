use mnemonic::seed;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;



/// Prints help
fn print_help() {
	println!("USAGE:");
	println!("    cargo run [OPTIONS] [--] [args]...");
	println!("ARGS:");
	println!("  --help						Print help");
	println!("  --entropy <entropy/filepath>				Generate mnemonic and seed from given entropy");
	println!("  --mnemonic <mnemonic/filepath>			Generate entropy and seed from given mnemonic");
	println!("  --check <mnemonic/filepath> <seed/filepath>		Check if given mnemonic generates given seed");
	println!("  --to_file <file>					Write output to file instead of stdout");
	println!("  --from_file						Load values from files. Arg params will be considered as file paths");
}

/// Checks whether multiple operations have been specified
///
/// # Arguments
///
///  * `entropy` - representation of entropy state. true if --entropy has been specified, false otherwise
///  * `mnemonic` - representation of mnemonic state. true if --mnemonic has been specified, false otherwise
///  * `check` - representation of check state. true if --check has been specified, false otherwise
fn check_multiple_operations(entropy:bool, mnemonic:bool, check:bool){
    if (entropy && mnemonic) || (entropy && check) || (mnemonic && check) {
        print_help();
        println!();
        println!("Multiple operations specified, exiting...");
        std::process::exit(1);
    }
}

/// Checks whether at least one operation have been specified
///
/// # Arguments
///
///  * `entropy` - representation of entropy state. true if --entropy has been specified, false otherwise
///  * `mnemonic` - representation of mnemonic state. true if --mnemonic has been specified, false otherwise
///  * `check` - representation of check state. true if --check has been specified, false otherwise
fn check_at_least_one_operation(entropy: bool, mnemonic: bool, check: bool) {
    if !(entropy || mnemonic || check) {
        print_help();
        println!();
        println!("Nothing to do, provide operation (--entropy, --mnemonic, --check), exiting...");
        std::process::exit(1);
    }
}

/// Checks whether operation with name <name> has been specified more than once
///
/// # Arguments
///
/// * `param` - representation of double definition. true if operation was previously(already) defined, false otherwise
/// * `name` - name of operation [--entropy, --mnemonic, --check]
fn check_double_definition(param: bool, name: &str) {
    if param {
        print_help();
        println!();
        println!("Double {} definition, exiting...", name);
        std::process::exit(1);
    }
}

/// Checks whether user gives parameter for operation
///
/// # Arguments
///
/// * `position` - position where parameters are expected
/// * `arguments_len` - number of arguments
/// * `name` - operation name
fn check_provided_params(position: usize, arguments_len: usize, name: &str) {
    if position >= arguments_len {
        print_help();
        println!();
        println!("{} parameter not provided, exiting...", name);
        std::process::exit(1);
    }
}

/// Checks whether given string has only albhabetic or whitespace characters
fn is_alphabetic_whitespace(text: &str) -> bool{
    for character in text.chars() {
        if !(character.is_alphabetic() || character.is_whitespace()) {
            return false;
        }
    }
    true
}

/// Checks whether given string is binary
fn is_binary(text: &str) -> bool {
    for character in text.chars() {
        if !(character == '0' || character == '1') {
            return false;
        }
    }
    true
}

/// Checks whether given string is hexadecimal
fn is_hexadecimal(text: &str) -> bool {
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

/// Load passphrase from user
fn load_passphrase() -> String{
    println!("Please enter passphrase: ");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase).expect("Error reading input");
    if passphrase.chars().last().unwrap() == '\n' { // remove trailing newline if there is one
        passphrase.pop();
    }
    passphrase
}

/// Parse Vec<u8> to hexadecimal string
fn to_hex_string(bytes: Vec<u8>) -> String {
    return bytes.iter().map(|b| format!("{:02x}", b)).collect();
}

/// Checks whether given mnemonic has valid format
///
/// # Arguments
///
/// * `mnemonic` - string which will be checked or path to file which content will be checked in case of from_file = true
/// * `from_file` - indication whether content of file should be checked.
fn check_valid_mnemonic(mnemonic: &str, from_file: bool) -> bool {
    if from_file {
        let file_content = std::fs::read_to_string(&mnemonic).expect("Unable to read file");
        return is_alphabetic_whitespace(&file_content);
    }
    return is_alphabetic_whitespace(&mnemonic);
}

/// Checks whether given entropy has valid format
///
/// # Arguments
///
/// * `entropy` - string which will be checked or path to file which content will be checked in case of from_file = true
/// * `from_file` - indication whether content of file should be checked.
fn check_valid_entropy(entropy: &str, from_file: bool) -> bool {
    if from_file {
        let file_content = std::fs::read_to_string(&entropy).expect("Unable to read file");
        return is_binary(&file_content) || is_hexadecimal(&file_content);
    }
    is_hexadecimal(entropy);
    return is_binary(&entropy) || is_hexadecimal(&entropy);
}

/// Checks whether given mnemonic and seed has valid format
///
/// # Arguments
///
/// * `mnemonic` - string which will be checked or path to file which content will be checked in case of from_file = true
/// * `seed` - string which will be checked or path to file which content will be checked in case of from_file = true
/// * `from_file` - indication whether content of file should be checked.
fn check_valid_check_params(mnemonic: &str, seed: &str, from_file: bool) -> bool {
    if from_file {
        let seed_file_content = std::fs::read_to_string(&seed).expect("Unable to read file");
        return check_valid_mnemonic(mnemonic, from_file) && is_hexadecimal(&seed_file_content);
    }
    return check_valid_mnemonic(mnemonic, from_file) && is_hexadecimal(seed);
}

/// Handle result of mnemonic operation
///
/// # Arguments
///
/// * `from_file` - load values from file if true
/// * `to_file` - write result to file if true
/// * `mnemonic` - mnemonic which will be processed or path to file which content will be processed
/// * `file_path` - path to file which will be opened if to_file = true
fn handle_mnemonic_result(from_file: bool, to_file: bool, mnemonic: &str, file_path: &str) {
    let pass_phrase = load_passphrase();

    let mut mnemonic_phrase = String::new();
    if from_file {
        mnemonic_phrase = std::fs::read_to_string(mnemonic).expect("Unable to read file");
        if mnemonic_phrase.chars().last().unwrap() == '\n' {
            mnemonic_phrase.pop(); // remove trailing newline if there is one
        }
    } else {
        mnemonic_phrase = mnemonic.to_string();
    }

    // Build final string
    let mut write_mnemonic = String::from("Entered mnemonic phrase: ");
    write_mnemonic.push_str(&mnemonic_phrase);
    let mut write_seed = String::from("Output seed: ");
    write_seed.push_str(&to_hex_string(seed(&mnemonic_phrase, Some(&pass_phrase))));
    let mut write_all = String::new();
    write_all.push_str(&write_mnemonic);
    write_all.push('\n');
    write_all.push_str(&write_seed);
    write_all.push('\n');

    if to_file {
        let path = Path::new(file_path);
        let display = path.display();

        // create file
        let mut file = match File::create(&path) {
            Err(why) => panic!("couldn't create {}: {}", display, why.description()),
            Ok(file) => file,
        };

        // write to file
        match file.write_all(write_all.as_bytes()) {
            Err(why) => panic!("couldn't write to {}: {}", display, why.description()),
            Ok(_) => println!("successfully wrote to {}", display),
        }
    } else {
        println!("{}", write_all);
    }
}

/// Handle result of entropy operation
///
/// # Arguments
///
/// * `from_file` - load values from file if true
/// * `to_file` - write result to file if true
/// * `entropy` - entropy which will be processed or path to file which content will be processed
/// * `file_path` - path to file which will be opened if to_file = true
fn handle_entropy_result(from_file: bool, to_file: bool, entropy: &str, file_path: &str) {
    let mut entropy_value: Vec<u8> = Vec::new();
    if from_file {
        entropy_value = std::fs::read_to_string(&entropy).expect("Unable to read file").bytes().collect();
    } else {
        entropy_value = entropy.bytes().collect();
    }

    // TODO call function, handle result

    if to_file {
        let path = Path::new(file_path);
        let display = path.display();

        // create file
        let mut file = match File::create(&path) {
            Err(why) => panic!("couldn't create {}: {}", display, why.description()),
            Ok(file) => file,
        };
        // TODO write result to file
    } else {
        // TODO write result to stdin
    }
}

/// Handle result of check operation
///
/// # Arguments
///
/// * `from_file` - load values from file if true
/// * `to_file` - write result to file if true
/// * `mnemonic` - mnemonic which will be processed ofr path to file which content will be processed
/// * `seed` - seed which will be processed ofr path to file which content will be processed
/// * `file_path` - path to file which will be opened if to_file = true
fn handle_check_result(from_file: bool, to_file: bool, mnemonic: &str, seed: &str, file_path: &str) {
    let mut mnemonic_value = String::new();
    let mut seed_value: Vec<u8> = Vec::new();

    if from_file {
        mnemonic_value = std::fs::read_to_string(mnemonic).expect("Unable to read file");
        seed_value = std::fs::read_to_string(seed).expect("Unable to read file").bytes().collect();
    } else {
        mnemonic_value = mnemonic.to_string();
        seed_value = seed.bytes().collect();
    }

    // TODO call function, handle result
    if to_file {
        let path = Path::new(file_path);
        let display = path.display();

        // create file
        let mut file = match File::create(&path) {
            Err(why) => panic!("couldn't create {}: {}", display, why.description()),
            Ok(file) => file,
        };
        // TODO write result to file
    } else {
        // TODO write result to stdin
    }
}


fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let mut _from_file = false;
    let mut _entropy = false;
    let mut _mnemonic = false;
    let mut _check = false;
    let mut _to_file = false;
    let mut skip_n:i8 = 0; // general purpose skip arg
    let mut entropy_value = String::new();
    let mut mnemonic_value: String = String::new();
    let mut check_mnemonic_value = String::new();
    let mut check_seed_value = String::new();
    let mut to_file_value = String::new();

    // collect arguments, check basic cases
    for position in 1..arguments.len() {
        if skip_n > 0 {
            skip_n -= 1;
            continue
        }
        if arguments[position] == "--entropy" {
            skip_n = 1;
            check_double_definition(_entropy, "--entropy");
            check_provided_params(position + 1, arguments.len(), "--entropy");
            entropy_value = arguments[position + 1].clone();
            _entropy = true;
        } else if arguments[position] == "--mnemonic" {
            skip_n = 1;
            check_double_definition(_mnemonic, "--mnemonic");
            check_provided_params(position + 1, arguments.len(), "--mnemonic");
            mnemonic_value = arguments[position + 1].clone();
            _mnemonic = true;
        } else if arguments[position] == "--check" {
            skip_n = 2;
            check_double_definition(_check, "--check");
            check_provided_params(position + 2, arguments.len(), "--check");
            check_mnemonic_value = arguments[position + 1].clone();
            check_seed_value = arguments[position + 2].clone();
            _check = true;
        } else if arguments[position] == "--to_file" {
            skip_n = 1;
            check_double_definition(_to_file, "--to_file");
            check_provided_params(position + 1, arguments.len(), "--to_file");
            to_file_value = arguments[position + 1].clone();
            _to_file = true;
        } else if arguments[position] == "--help" {
            return print_help();
        } else if arguments[position] == "--from_file" {
            check_double_definition(_from_file, "--from_file");
            _from_file = true;
        } else {
            print_help();
            println!();
            println!("Unexpected argument: {}\n", arguments[position]);
            std::process::exit(1);
        }
    }

    // check other cases
    check_at_least_one_operation(_entropy, _mnemonic, _check);
    check_multiple_operations(_entropy, _mnemonic, _check);

    //check format of params, call results
    if _entropy {
        if !check_valid_entropy(&entropy_value, _from_file) {
            println!("Entropy parameter invalid format, only hexadecimal(even length) or binary format accepted\n");
            std::process::exit(1);
        }
        handle_entropy_result(_from_file, _to_file, &entropy_value, &to_file_value);
    } else if _mnemonic {
        if !check_valid_mnemonic(&mnemonic_value, _from_file) {
            println!("Mnemonic parameter invalid format, only alphabetic and whitespace characters accepted\n");
            std::process::exit(1);
        }
        handle_mnemonic_result(_from_file, _to_file, &mnemonic_value, &to_file_value);
    } else if _check {
        if !check_valid_check_params(&check_mnemonic_value, &check_seed_value , _from_file) {
            println!("Check parameters invalid format, exiting...\n");
            std::process::exit(1);
        }
        handle_check_result(_from_file, _to_file, &check_mnemonic_value, &check_seed_value, &to_file_value);
    }
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