mod util;

use mnemonic::{entropy_to_mnemonic, mnemonic_to_entropy, mnemonic_to_seed};
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
        eprintln!("Double {} definition, exiting...", name);
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
        eprintln!("{} parameter not provided, exiting...", name);
        std::process::exit(1);
    }
}

/// Load passphrase from user
fn load_passphrase() -> Result<String, std::io::Error> {
    println!("Please enter passphrase: ");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase)?;
    if let Some('\n') = passphrase.chars().last() { // remove trailing newline if there is one
        passphrase.pop();
    }
    Ok(passphrase)
}

/// Strip newline, if present
fn strip_newline(input: &mut String) {
    if let Some('\n') = input.chars().last() {
        input.pop();
    } 
}

/// Load file contents
fn load_from_file(filename: &str) -> Result<String, std::io::Error> {
    Ok(std::fs::read_to_string(&filename)?)
}

/// Parse Vec<u8> to hexadecimal string
fn to_hex_string(bytes: Vec<u8>) -> String {
    return bytes.iter().map(|b| format!("{:02x}", b)).collect();
}

/// Checks whether given mnemonic has valid format
fn check_valid_mnemonic(mnemonic: &str) -> bool {
    return is_alphabetic_whitespace(&mnemonic);
}

/// Checks whether given entropy has valid format
fn check_valid_entropy(entropy: &str) -> bool {
    return is_binary(&entropy) || is_hexadecimal(&entropy);
}

/// Checks whether given mnemonic and seed has valid format
fn check_valid_check_params(mnemonic: &str, seed: &str) -> bool {
    return check_valid_mnemonic(mnemonic) && is_hexadecimal(seed);
}

/// Handle result of mnemonic operation
///
/// # Arguments
///
/// * `to_file` - write result to file if Some
/// * `mnemonic` - mnemonic which will be processed or path to file which content will be processed
fn handle_mnemonic_result(to_file: &Option<String>, mnemonic: &str) -> Result<i32, std::io::Error> {
    let initial_entropy = match mnemonic_to_entropy(&mnemonic) {
        Err(error) => {
            eprintln!("Input error: {}", error);
            return Ok(1);
        },
        Ok(entropy) => entropy,
    };
    let pass_phrase = load_passphrase()?;

    // Build final string
    let mut write_mnemonic = String::from("Entered mnemonic phrase: ");
    write_mnemonic.push_str(&mnemonic);
    let mut write_entropy = String::from("Initial entropy: ");
    write_entropy.push_str(&to_hex_string(initial_entropy));
    let mut write_seed = String::from("Output seed: ");
    write_seed.push_str(&to_hex_string(mnemonic_to_seed(&mnemonic, Some(&pass_phrase))));
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
        let mut file = File::create(&path)?;

        // write to file
        file.write_all(write_all.as_bytes())?;
        println!("successfully wrote to {}", display);
    } else {
        print!("{}", write_all);
    }

    Ok(0)
}


/// Handle result of entropy operation
///
/// # Arguments
///
/// * `to_file` - write result to file if Some
/// * `entropy` - entropy which will be processed or path to file which content will be processed
fn handle_entropy_result(to_file: &Option<String>, entropy: &str) -> Result<i32, std::io::Error> {
    let entropy_value: Vec<u8>;
    let mut input_entropy = String::from(entropy);

    if is_binary(&input_entropy) { // if input in binary, convert it to hexadecimal
        input_entropy = match binary_to_hex(&input_entropy) {
            Err(error) => {
                eprintln!("Input error: {}", error);
                return Ok(1);
            },
            Ok(entropy) => entropy,
        }
    }

    entropy_value = match decode_hex(&input_entropy) {
        Err(_) => {
            eprintln!("Input error: Cannot decode hex!");
            return Ok(1);
        },
        Ok(entropy) => entropy,
    };

    let mnemonic_result = match entropy_to_mnemonic(&entropy_value) {
        Err(error) => {
            eprintln!("Input error: {}", error);
            return Ok(1);
        },
        Ok(mnemonic) => mnemonic,
    };

    let pass_phrase = load_passphrase()?;
    let seed = to_hex_string(mnemonic_to_seed(&mnemonic_result, Some(&pass_phrase)));

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
        let mut file = File::create(&path)?;

        // write to file
        file.write_all(write_all.as_bytes())?;
        println!("successfully wrote to {}", display);
    } else {
        print!("{}", write_all);
    }

    Ok(0)
}

/// Handle result of check operation
///
/// # Arguments
///
/// * `to_file` - write result to file if Some
/// * `mnemonic` - mnemonic which will be processed ofr path to file which content will be processed
/// * `seed` - seed which will be processed ofr path to file which content will be processed
fn handle_check_result(to_file: &Option<String>, mnemonic: &str, seed: &str) -> Result<i32, std::io::Error> {
    let pass_phrase = load_passphrase()?;
    let computed_seed = mnemonic_to_seed(&mnemonic, Some(&pass_phrase));
    let hex_init_seed = match decode_hex(&seed) {
        Err(_) => {
            eprintln!("Input error: Cannot decode hex!");
            return Ok(1);
        },
        Ok(entropy) => entropy,
    };

    // Build final string
    let mut result:String = String::new();
    if computed_seed == hex_init_seed {
        result.push_str("OK\n");
    } else {
        result.push_str("NOK\n");
    }
    let mut write_mnemonic = String::from("Input mnemonic: ");
    write_mnemonic.push_str(&mnemonic);
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
        let mut file = File::create(&path)?;

        // write to file
        file.write_all(write_all.as_bytes())?;
        
        println!("successfully wrote to {}", display);
    } else {
        print!("{}", write_all);
    }

    Ok(0)
}

struct Options {
    from_file: bool,
    to_file: Option<String>,
    entropy: Option<String>,
    mnemonic: Option<String>,
    check: Option<(String, String)>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            from_file: false,
            to_file: Option::default(),
            entropy: Option::default(),
            mnemonic: Option::default(),
            check: Option::default(),
        }
    }
}

impl Options {

    /// Checks whether multiple operations have been specified
    fn check_multiple_operations(&self){
        if self.entropy.is_some() as u8 + self.mnemonic.is_some() as u8 + self.check.is_some() as u8 > 1 {
            print_help();
            println!();
            eprintln!("Multiple operations specified, exiting...");
            std::process::exit(1);
        }
    }

    /// Checks whether at least one operation have been specified
    fn check_at_least_one_operation(&self) {
        if !(self.entropy.is_some() || self.mnemonic.is_some() || self.check.is_some()) {
            print_help();
            println!();
            eprintln!("Nothing to do, provide operation (--entropy, --mnemonic, --check), exiting...");
            std::process::exit(1);
        }
    }

    fn load(&mut self) -> Result<(), std::io::Error> {
        if self.from_file {
            if self.entropy.is_some() {
                self.entropy = Some(load_from_file(self.entropy.as_ref().unwrap())?)
            }
            if self.mnemonic.is_some() {
                self.mnemonic = Some(load_from_file(self.mnemonic.as_ref().unwrap())?)
            }
            if self.check.is_some() {
                let (check_mnemonic, check_seed) = self.check.as_ref().unwrap();
                self.check = Some((load_from_file(check_mnemonic)?, load_from_file(check_seed)?))
            }
        }
        Ok(())
    }

    fn clean_input(&mut self) {
        if self.entropy.is_some() {
            strip_newline(self.entropy.as_mut().unwrap());
        }
        if self.mnemonic.is_some() {
            strip_newline(self.mnemonic.as_mut().unwrap());
        }
        if self.check.is_some() {
            let (check_mnemonic, check_seed) = self.check.as_mut().unwrap();
            strip_newline(check_mnemonic);
            strip_newline(check_seed);
        }
    }

    fn check_data(&self) {
        if let Some(entropy) = self.entropy.as_ref() {
            if !check_valid_entropy(entropy) {
                eprintln!("Entropy parameter invalid format, only hexadecimal or binary format accepted");
                std::process::exit(1);
            }
        }
        if let Some(mnemonic) = self.mnemonic.as_ref() {
            if !check_valid_mnemonic(mnemonic) {
                eprintln!("Mnemonic parameter invalid format, only alphabetic and whitespace characters accepted");
                std::process::exit(1);
            }
        }
        if let Some((check_mnemonic, check_seed)) = self.check.as_ref() {
            if !check_valid_check_params(check_mnemonic, check_seed) {
                eprintln!("Check parameters invalid format, exiting...");
                std::process::exit(1);
            }
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
                options.entropy = Some(arguments[position + 1].clone());
            },
            "--mnemonic" => {
                skip_n = 1;
                check_double_definition(options.mnemonic.is_some(), &arguments[position]);
                check_provided_params(position + 1, arguments.len(), &arguments[position]);
                options.mnemonic = Some(arguments[position + 1].clone());
            },
            "--check" => {
                skip_n = 2;
                check_double_definition(options.check.is_some(), &arguments[position]);
                check_provided_params(position + 2, arguments.len(), &arguments[position]);
                options.check = Some((arguments[position + 1].clone(), arguments[position + 2].clone()));
            },
            "--to_file" => {
                skip_n = 1;
                check_double_definition(options.to_file.is_some(), &arguments[position]);
                check_provided_params(position + 1, arguments.len(), &arguments[position]);
                options.to_file = Some(arguments[position + 1].clone())
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

    if let Err(_) = options.load() {
        eprintln!("Input file could not be read!");
        std::process::exit(1);
    }

    options.clean_input();
    options.check_data();

    // check format of params, call results
    let result = if options.entropy.is_some() {
        handle_entropy_result(&options.to_file, &options.entropy.unwrap())
    } else if options.mnemonic.is_some() {
        handle_mnemonic_result(&options.to_file, &options.mnemonic.unwrap())
    } else if options.check.is_some() {
        let (check_mnemonic, check_seed) = options.check.unwrap();
        handle_check_result(&options.to_file, &check_mnemonic, &check_seed)
    } else {
        unreachable!()
    };

    if result.is_err() {
        eprintln!("IO error: {}", result.unwrap_err().description());
        std::process::exit(1);
    }
    std::process::exit(result.unwrap());
}