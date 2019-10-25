use mnemonic::seed;


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

fn check_multiple_params(entropy:bool, mnemonic:bool, check:bool) -> bool{
    return (entropy && mnemonic) || (entropy && check) || (mnemonic && check);
}

fn check_double_definition(param: bool, name: &str) {
    if param {
        println!("Double {} definition, exiting...", name);
        std::process::exit(1);
    }
}

fn check_provided_params(position: usize, arguments_len: usize, name: &str) {
    if position >= arguments_len {
        println!("{} parameter not provided, exiting...", name);
        std::process::exit(1);
    }
}


fn to_hex_string(bytes: Vec<u8>) -> String {
    return bytes.iter().map(|b| format!("{:02x}", b)).collect();
}

fn handle_mnemonic_result(from_file: bool, to_file: bool, mnemonic: &str, file_path: &str) {
    println!("Please enter passphrase: ");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase).expect("Error reading input");
    if passphrase.chars().last().unwrap() == '\n' { // remove trailing newline if there is one
        passphrase.pop();
    }
    if to_file {

    } else {
        println!("Entered mnemonic phrase: {}", mnemonic);
        println!("Output seed: {}", to_hex_string(seed(&mnemonic, Some(&passphrase))));
    }

}

fn handle_entropy_result(from_file: bool, to_file: bool, entropy: &str, file_path: &str) {

}

fn handle_check_result(from_file: bool, to_file: bool, mnemonic: &str, seed: &str, file_path: &str) {
    
}

fn check_valid_mnemonic(mnemonic: &str, from_file: bool) -> bool {
    for character in mnemonic.chars() {
        if !(character.is_alphabetic() || character.is_whitespace()) {
            return false;
        }
    }
    return true;
}

fn check_valid_entropy(entropy: &str, from_file: bool) -> bool {
    true
}

fn check_valid_check_params(mnemonic: &str, seed: &str, from_file: bool) -> bool {
    true
}

fn check_valid_file_path(file_path: &str) -> bool {
    true
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
        }
    }

    // check other cases
    if check_multiple_params(_entropy, _mnemonic, _check) {
        println!("Multiple operations specified, exiting...");
        std::process::exit(1);
    }
    if _to_file {
        if !check_valid_file_path(&to_file_value) {
            println!("File path provided for --to_file argument is not valid, exiting...");
            std::process::exit(1);
        }
    }

    //check format of params, call results
    if _entropy {
        check_valid_entropy(&entropy_value, _from_file);
        handle_entropy_result(_from_file, _to_file, &entropy_value, &to_file_value);
    } else if _mnemonic {
        check_valid_mnemonic(&mnemonic_value, _from_file);
        handle_mnemonic_result(_from_file, _to_file, &mnemonic_value, &to_file_value);
    } else if _check {
        check_valid_check_params(&check_mnemonic_value, &check_seed_value , _from_file);

    }

}
