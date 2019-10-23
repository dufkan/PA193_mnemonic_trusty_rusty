use std::io::Write;
use std::str::FromStr;

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

struct Opt {
    from_file: bool
}

fn check_multiple_params(entropy:bool, mnemonic:bool, check:bool) -> bool{
    return (entropy && mnemonic) || (entropy && check) || (mnemonic && check)
}

fn main() {
	println!("Hello, world!");
    let arguments: Vec<String> = std::env::args().collect();
    let mut _from_file = false;
    let mut _entropy = false;
    let mut _mnemonic = false;
    let mut _check = false;
    let mut _to_file = false;

    for mut position in 1..arguments.len() {
        if arguments[position] == "--entropy" {
            if _entropy {
                println!("Double entropy definition, exiting...");
                std::process::exit(1);
            }
            if position + 1 >= arguments.len() {
                println!("--entropy parameter not provided, exiting...");
                std::process::exit(1);
            }
            _entropy = true;
        }



        if arguments[position] == "--help" {
            return print_help();
        }
        if check_multiple_params(_entropy, _mnemonic, _check) {
            println!("Multiple operations specified, exiting...");
            std::process::exit(1);
        }
    }
    println!("test");
    
}
