//! Load a `bogo.toml` and `secrets.toml` the way the daemon does, and print the result.
//!
//! `cargo run -q -p bogo-config --example check -- <bogo.toml> <secrets.toml>`
//! With no arguments it loads `~/.bogo/bogo.toml` and `~/.bogo/secrets.toml`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let loaded = match args.as_slice() {
        [] => bogo_config::Config::load_default(),
        [bogo, secrets] => {
            bogo_config::Config::load(Path::new(bogo), Path::new(secrets), home.as_deref())
        }
        _ => {
            eprintln!("usage: check [<bogo.toml> <secrets.toml>]");
            return ExitCode::from(2);
        }
    };
    match loaded {
        Ok(cfg) => {
            println!("{cfg:#?}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("refused: {e}");
            ExitCode::FAILURE
        }
    }
}
