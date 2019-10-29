mod util;

use mnemonic::{entropy_to_mnemonic, mnemonic_to_entropy, seed};
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use util::{is_hexadecimal, decode_hex, is_binary, is_alphabetic_whitespace, binary_to_hex};

/// Prints help
fn print_help() {
	println!("USAGE:");
	println!("    {} [ARGS]", std::env::args().next().unwrap_or(String::from("cargo run --")));
	println!("ARGS:");
	println!("  --help                                         Print help");
	println!("  --entropy <entropy/filepath>                   Generate mnemonic and seed from given entropy");
	println!("  --mnemonic <mnemonic/filepath>                 Generate entropy and seed from given mnemonic");
	println!("  --check <mnemonic/filepath> <seed/filepath>    Check if given mnemonic generates given seed");
	println!("  --to_file <file>                               Write output to file instead of stdout");
	println!("  --from_file                                    Load values from files. Arg params will be considered as file paths");
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

/// Load passphrase from user
fn load_passphrase() -> String{
    println!("Please enter passphrase: ");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase).expect("Error reading input");
    if let Some('\n') = passphrase.chars().last() { // remove trailing newline if there is one
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
        let mut file_content = std::fs::read_to_string(&entropy).expect("Unable to read file");
        if let Some('\n') = file_content.chars().last() {
            file_content.pop(); // remove trailing newline if there is one
        }
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
        let mut seed_file_content = std::fs::read_to_string(&seed).expect("Unable to read file");
        if let Some('\n') = seed_file_content.chars().last() {
            seed_file_content.pop(); // remove trailing newline if there is one
        }
        return check_valid_mnemonic(mnemonic, from_file) && is_hexadecimal(&seed_file_content);
    }
    return check_valid_mnemonic(mnemonic, from_file) && is_hexadecimal(seed);
}

/// Handle result of mnemonic operation
///
/// # Arguments
///
/// * `from_file` - load values from file if true
/// * `to_file` - write result to file if Some
/// * `mnemonic` - mnemonic which will be processed or path to file which content will be processed
fn handle_mnemonic_result(from_file: bool, to_file: &Option<&str>, mnemonic: &str) {
    let mut mnemonic_phrase;

    if from_file {
        mnemonic_phrase = std::fs::read_to_string(mnemonic).expect("Unable to read file");
        if let Some('\n') = mnemonic_phrase.chars().last() {
            mnemonic_phrase.pop(); // remove trailing newline if there is one
        }
    } else {
        mnemonic_phrase = mnemonic.to_string();
    }

    let initial_entropy: Vec<u8> = mnemonic_to_entropy(&mnemonic_phrase);
    let pass_phrase = load_passphrase();

    // Build final string
    let mut write_mnemonic = String::from("Entered mnemonic phrase: ");
    write_mnemonic.push_str(&mnemonic_phrase);
    let mut write_entropy = String::from("Initial entropy: ");
    write_entropy.push_str(&to_hex_string(initial_entropy));
    let mut write_seed = String::from("Output seed: ");
    write_seed.push_str(&to_hex_string(seed(&mnemonic_phrase, Some(&pass_phrase))));
    let mut write_all = String::new();
    write_all.push_str(&write_mnemonic);
    write_all.push('\n');
    write_all.push_str(&write_entropy);
    write_all.push('\n');
    write_all.push_str(&write_seed);
    write_all.push('\n');

    if to_file.is_some() {
        let path = Path::new(to_file.as_ref().unwrap());
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
        print!("{}", write_all);
    }
}


/// Handle result of entropy operation
///
/// # Arguments
///
/// * `from_file` - load values from file if true
/// * `to_file` - write result to file if Some
/// * `entropy` - entropy which will be processed or path to file which content will be processed
fn handle_entropy_result(from_file: bool, to_file: &Option<&str>, entropy: &str) {
    let entropy_value: Vec<u8>;
    let mut input_entropy = String::from(entropy);

    if from_file {
        input_entropy = std::fs::read_to_string(&entropy).expect("Unable to read file");
    }

    if let Some('\n') = input_entropy.chars().last() {
        input_entropy.pop(); // remove trailing newline if there is one
    }

    if is_binary(&input_entropy) { // if input in binary, convert it to hexadecimal
        input_entropy = binary_to_hex(&input_entropy);
    }

    entropy_value = decode_hex(&input_entropy).ok().unwrap();
    let mnemonic_result = entropy_to_mnemonic(&entropy_value);

    let pass_phrase = load_passphrase();
    let seed = to_hex_string(seed(&mnemonic_result, Some(&pass_phrase)));

    // Build final string
    let mut write_entropy = String::from("Entered entropy: ");
    write_entropy.push_str(&input_entropy);
    let mut write_mnemonic = String::from("Output mnemonic: ");
    write_mnemonic.push_str(&mnemonic_result);
    let mut write_seed = String::from("Output seed: ");
    write_seed.push_str(&seed);
    let mut write_all = String::new();
    write_all.push_str(&write_entropy);
    write_all.push('\n');
    write_all.push_str(&write_mnemonic);
    write_all.push('\n');
    write_all.push_str(&write_seed);
    write_all.push('\n');

    if to_file.is_some() {
        let path = Path::new(to_file.as_ref().unwrap());
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
        print!("{}", write_all);
    }
}

/// Handle result of check operation
///
/// # Arguments
///
/// * `from_file` - load values from file if true
/// * `to_file` - write result to file if Some
/// * `mnemonic` - mnemonic which will be processed ofr path to file which content will be processed
/// * `seed` - seed which will be processed ofr path to file which content will be processed
fn handle_check_result(from_file: bool, to_file: &Option<&str>, mnemonic: &str, seed_input: &str) {
    let mut mnemonic_value;
    let mut input_seed;

    if from_file {
        mnemonic_value = std::fs::read_to_string(mnemonic).expect("Unable to read file");
        input_seed = std::fs::read_to_string(&seed_input).expect("Unable to read file");
    } else {
        mnemonic_value = mnemonic.to_string();
        input_seed = seed_input.to_string();
    }

    if let Some('\n') = mnemonic_value.chars().last() {
        mnemonic_value.pop(); // remove trailing newline if there is one
    }
    if let Some('\n') = input_seed.chars().last() {
        input_seed.pop(); // remove trailing newline if there is one
    }

    let pass_phrase = load_passphrase();
    let computed_seed = seed(&mnemonic_value, Some(&pass_phrase));
    let hex_init_seed = decode_hex(&input_seed).ok().unwrap();


    // Build final string
    let mut result:String = String::new();
    if computed_seed == hex_init_seed {
        result.push_str("OK\n");
    } else {
        result.push_str("NOK\n");
    }
    let mut write_mnemonic = String::from("Input mnemonic: ");
    write_mnemonic.push_str(&mnemonic_value);
    let mut write_input_seed = String::from("Input seed: ");
    write_input_seed.push_str(&to_hex_string(hex_init_seed));
    let mut write_seed = String::from("Output seed: ");
    write_seed.push_str(&to_hex_string(computed_seed));
    let mut write_all = String::new();
    write_all.push_str(&write_mnemonic);
    write_all.push('\n');
    write_all.push_str(&write_input_seed);
    write_all.push('\n');
    write_all.push_str(&write_seed);
    write_all.push('\n');
    write_all.push_str(&result);

    if to_file.is_some() {
        let path = Path::new(to_file.as_ref().unwrap());
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
        print!("{}", write_all);
    }
}

struct Options<'a> {
    from_file: bool,
    to_file: Option<&'a str>,
    entropy: Option<&'a str>,
    mnemonic: Option<&'a str>,
    check: Option<(&'a str, &'a str)>,
}

impl<'a> Default for Options<'a> {
    fn default() -> Options<'a> {
        Options {
            from_file: false,
            to_file: Option::default(),
            entropy: Option::default(),
            mnemonic: Option::default(),
            check: Option::default(),
        }
    }
}

impl<'a> Options<'a> {

    /// Checks whether multiple operations have been specified
    fn check_multiple_operations(&self){
        if self.entropy.is_some() as u8 + self.mnemonic.is_some() as u8 + self.check.is_some() as u8 > 1 {
            print_help();
            println!();
            println!("Multiple operations specified, exiting...");
            std::process::exit(1);
        }
    }

    /// Checks whether at least one operation have been specified
    fn check_at_least_one_operation(&self) {
        if !(self.entropy.is_some() || self.mnemonic.is_some() || self.check.is_some()) {
            print_help();
            println!();
            println!("Nothing to do, provide operation (--entropy, --mnemonic, --check), exiting...");
            std::process::exit(1);
        }
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let mut options = Options::default();
    let mut skip_n: i8 = 0; // general purpose skip arg

    for position in 1..arguments.len() {
        if skip_n > 0 {
            skip_n -= 1;
            continue
        }
        match arguments[position].as_str() {
            "--entropy" => {
                skip_n = 1;
                check_double_definition(options.entropy.is_some(), &arguments[position]);
                check_provided_params(position + 1, arguments.len(), &arguments[position]);
                options.entropy = Some(&arguments[position + 1]);
            },
            "--mnemonic" => {
                skip_n = 1;
                check_double_definition(options.mnemonic.is_some(), &arguments[position]);
                check_provided_params(position + 1, arguments.len(), &arguments[position]);
                options.mnemonic = Some(&arguments[position + 1]);
            },
            "--check" => {
                skip_n = 2;
                check_double_definition(options.check.is_some(), &arguments[position]);
                check_provided_params(position + 2, arguments.len(), &arguments[position]);
                options.check = Some((&arguments[position + 1], &arguments[position + 2]));
            },
            "--to_file" => {
                skip_n = 1;
                check_double_definition(options.to_file.is_some(), &arguments[position]);
                check_provided_params(position + 1, arguments.len(), &arguments[position]);
                options.to_file = Some(&arguments[position + 1])
            },
            "--help" => return print_help(),
            "--from_file" => {
                check_double_definition(options.from_file, &arguments[position]);
                options.from_file = true;
            },
            _ => {
                print_help();
                println!();
                println!("Unexpected argument: {}", arguments[position]);
                std::process::exit(1);
            }
        }
    }

    // check other cases
    options.check_at_least_one_operation();
    options.check_multiple_operations();

    // check format of params, call results
    if options.entropy.is_some() {
        let entropy = options.entropy.unwrap();
        if !check_valid_entropy(&entropy, options.from_file) {
            println!("Entropy parameter invalid format, only hexadecimal(even length) or binary format accepted");
            std::process::exit(1);
        }
        handle_entropy_result(options.from_file, &options.to_file, &entropy);
    } else if options.mnemonic.is_some() {
        let mnemonic = options.mnemonic.unwrap();
        if !check_valid_mnemonic(&mnemonic, options.from_file) {
            println!("Mnemonic parameter invalid format, only alphabetic and whitespace characters accepted");
            std::process::exit(1);
        }
        handle_mnemonic_result(options.from_file, &options.to_file, &mnemonic);
    } else if options.check.is_some() {
        let (check_mnemonic, check_seed) = options.check.unwrap();
        if !check_valid_check_params(&check_mnemonic, &check_seed, options.from_file) {
            println!("Check parameters invalid format, exiting...");
            std::process::exit(1);
        }
        handle_check_result(options.from_file, &options.to_file, &check_mnemonic, &check_seed);
    }
}