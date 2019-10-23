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

fn main() {
	println!("Hello, world!");
	
	for arg in std::env::args().skip(1) {
		if &arg == "--help" {
			return print_help();
		} 
		else {
			writeln!(std::io::stderr(), "Invalid arguments, exiting...").unwrap();
			print_help();
			std::process::exit(1);
		}
	}
	true;
}
